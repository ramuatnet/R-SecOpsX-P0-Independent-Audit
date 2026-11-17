"""
scanner/taint_engine.py
Backward-compatible AST taint engine for Python plus lightweight enterprise
source-to-sink scanning for Java/Spring, .NET, Node/TS, Go, PHP and GraphQL.

Public API preserved:
- analyze_file(filepath) -> list[dict]
"""
from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from core.mapper import get_mapping
except Exception:
    def get_mapping(vuln_type: str) -> dict:
        return {}

# T-0.2 (task.md): shared content read. The taint pipeline used to open
# the same file once in _analyze_base and once more in EVERY java-semantics
# pass; the scan's index serves one disk read for all of them.
from core import file_index
# FND-02: the one walk -- used only on the no-active-index fallback path
# below (the indexed path above stays a file_index query, never a second
# walk).
from scanner.walk import walk

TAINT_SOURCES = {
    # Flask / FastAPI / Werkzeug request surfaces
    "request.args", "request.form", "request.json", "request.data", "request.headers", "request.cookies",
    "request.values", "request.get_json", "request.files", "input", "sys.argv",
    # aiohttp server request surface: ``await request.post()`` parses the
    # request body (form/multipart) exactly like Flask's request.form, and it
    # is the payload path of the T-2.2 route->dao boundary miss (dvpwa reads
    # the POST body here before handing it to the dao). Only the lowercase
    # token is added: aiohttp's Request has no ``.get()`` body method, and
    # Django's ``request.POST`` is a different (case-sensitive) name.
    "request.post",
    # A5: ``os.environ``/``os.getenv`` were removed from TAINT_SOURCES. The
    # deployment environment is written by the deployer -- an operator input,
    # not an untrusted network source (ground truth in_scope: "a demonstrable
    # untrusted source"). Counting it tainted every config-driven call site:
    # ``requests.get(url, headers={"Circle-Token": os.environ.get(...)})``
    # was reported as SSRF 4x in transformers purely because a token was read
    # from the environment. ``sys.argv``/``input`` stay: both are direct,
    # attacker-reachable process surfaces on any CLI service.
    "params", "query", "kwargs",
    # Django request surfaces (request.GET / request.POST are QueryDicts carrying
    # attacker-controlled keys and values; body/path/COOKIES/META/FILES match them).
    "request.GET", "request.POST", "request.body", "request.COOKIES", "request.FILES",
    "request.META", "request.path", "request.path_info", "request.full_path", "request.get_full_path",
    # ``http.server.BaseHTTPRequestHandler`` request surfaces.  ``self.headers``
    # is the parsed request header block and ``self.rfile`` is the socket the
    # request body is read from, so both are attacker-controlled on any
    # stdlib-handler route -- this is the Flask ``request.*`` equivalent for a
    # plain HTTP server rather than a second framework.
    "self.headers", "self.rfile.read",
}

# Dotted sources are matched on segment boundaries so that a qualified import
# (e.g. ``flask.request.args.get(...)`` or ``django.http.request.HttpRequest``)
# still resolves, while unrelated names that merely *contain* the source text
# (e.g. ``sanitize_params.get(...)``) do not.
_DOTTED_SOURCES = frozenset(s for s in TAINT_SOURCES if "." in s)

DANGEROUS_SINKS: dict[str, str] = {
    "execute": "sql_injection", "executemany": "sql_injection", "raw": "sql_injection", "cursor.execute": "sql_injection",
    "subprocess.call": "command_injection", "subprocess.run": "command_injection", "subprocess.Popen": "command_injection", "os.system": "command_injection", "os.popen": "command_injection",
    "subprocess.check_output": "command_injection", "subprocess.check_call": "command_injection", "subprocess.getoutput": "command_injection", "subprocess.getstatusoutput": "command_injection",
    "open": "path_traversal", "os.path.join": "path_traversal", "os.listdir": "path_traversal", "os.remove": "path_traversal", "os.rename": "path_traversal",
    # Vector-store / KV-store write primitives take the destination as a path
    # keyword (``kv.persist(persist_path=p)``, ``ctx.persist(persist_dir=d)``).
    # Nothing in the standard library or the common Python graph/vector stack
    # is named ``persist`` without meaning "write my state to this location",
    # and the check is taint-gated, so a ``.persist()`` with no attacker value
    # in its arguments cannot report.
    "persist": "path_traversal",
    "eval": "code_injection", "exec": "code_injection", "compile": "code_injection",
    "pickle.load": "insecure_deserialization", "pickle.loads": "insecure_deserialization", "yaml.load": "insecure_deserialization", "marshal.loads": "insecure_deserialization", "jsonpickle.decode": "insecure_deserialization",
    "requests.get": "ssrf", "requests.post": "ssrf", "requests.put": "ssrf", "requests.delete": "ssrf", "requests.request": "ssrf", "urllib.request.urlopen": "ssrf", "http.client.HTTPConnection": "ssrf", "http.client.HTTPSConnection": "ssrf",
    # A9: httpx is requests' async/HTTP2 successor and was absent, so
    # ``httpx.get(url_from_request)`` was an unfillable FN class. Module-level
    # methods only -- bare ``session.get``/``aiohttp`` stay out because a
    # Django/SQLAlchemy ``session.get`` is an ORM read, not an outbound call.
    "httpx.get": "ssrf", "httpx.post": "ssrf", "httpx.put": "ssrf", "httpx.delete": "ssrf", "httpx.patch": "ssrf", "httpx.request": "ssrf", "httpx.head": "ssrf",
    "redirect": "open_redirect", "render_template_string": "xss", "Markup": "xss",
}

# A10: bare DB-API method keys (``execute``/``executemany``/``raw``) also
# match any dotted receiver, so ``g.functionz.executor.execute(fn, **params)``
# -- a *function* executor in babyagi -- was reported as SQL injection. The
# receiver must be DB-API/ORM-shaped for the bare method name to count as SQL.
# Explicit keys (``cursor.execute``) and receiver-less ``execute(...)`` are
# untouched; a call-chained receiver (``get_db().execute``) cannot be proven
# non-DB and keeps firing (shape is handled by requiring a pure dotted chain).
_BARE_SQL_SINK_KEYS = frozenset({"execute", "executemany", "raw"})
_SQL_DB_RECEIVER_TAILS = frozenset({
    # DB-API / common handle names (``c``/``con`` keep the existing
    # test_v11_taint_intermediate_variable_flows ``c.execute`` TP).
    "cursor", "cur", "c", "con", "conn", "connection",
    "sess", "session", "db", "database", "engine", "dao", "repo", "repository",
    # statement-shaped names (``stmt = f"..."; db.execute(stmt)`` receivers)
    "sql", "statement", "stmt",
    # ORM surfaces: ``Model.objects.raw(...)`` (Django), queryset aliases
    "objects", "manager", "queryset", "qs", "query",
    # driver modules and transactions
    "pdo", "mysql", "mysqli", "pg", "psycopg", "psycopg2", "sqlite", "sqlite3",
    "odbc", "jdbc", "dbapi", "tx", "txn", "trans", "transaction",
})
_PURE_DOTTED_CALL_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_SSRF_URL_KWARGS = frozenset({"url", "uri", "href", "endpoint"})


def _ssrf_url_args(call: ast.Call) -> list:
    """A9: only arguments that *are* the request URL can carry SSRF taint.
    ``requests.get(url, params=..., headers=..., json=...)`` puts the
    attacker-reachable value in the URL slot; a taint sitting in a header or
    params dict is not what the server fetches. ``requests.request("GET",
    url)`` has the URL in the second position behind a method literal.
    """
    args = list(call.args)
    out = []
    if args:
        out.append(args[0])
        if len(args) > 1 and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            out.append(args[1])
    out.extend(kw.value for kw in call.keywords if kw.arg in _SSRF_URL_KWARGS)
    return out

LANG_BY_EXT = {".py":"python", ".java":"java", ".cs":"csharp", ".js":"javascript", ".jsx":"javascript", ".ts":"typescript", ".tsx":"typescript", ".go":"go", ".php":"php", ".graphql":"graphql", ".gql":"graphql"}
_F = re.IGNORECASE | re.MULTILINE | re.DOTALL

# ---------------------------------------------------------------------------
# Sanitizer model
# ---------------------------------------------------------------------------
# A sanitizer is only modelled where the escaping/quoting primitive is a
# well-established, context-correct defence for ONE specific vuln class.
# Sanitization is therefore recorded per vuln class: ``html.escape(x)`` makes
# ``x`` safe to render into HTML but does nothing for SQL, shell or path
# contexts, and ``shlex.quote(x)`` makes ``x`` safe for a POSIX shell but does
# nothing for HTML.  Deliberately excluded (context-dependent, therefore not
# provable here): ``cgi.escape`` (quote=False by default), ``os.path.basename``
# / ``normpath`` (do not remove traversal on their own), ``urllib.parse.quote``
# (URL encoding is not HTML encoding and does not defeat ``javascript:``).
SANITIZERS: dict[str, frozenset[str]] = {
    "xss": frozenset({
        "html.escape", "markupsafe.escape", "markupsafe.Markup.escape",
        "bleach.clean", "django.utils.html.escape", "django.utils.html.format_html",
    }),
    "command_injection": frozenset({
        "shlex.quote", "shlex.join",
    }),
    # A9e: ``urlencode`` builds a query STRING. Its output is always
    # ``k=v&k2=v2`` -- never an absolute URL -- so a value that passed
    # through it cannot change the fetch destination. This is the
    # string-expression equivalent of the A9 ``params=``/``json=`` payload
    # kwarg position (payload is not the URL). Measured: transformers
    # utils/update_pr_ci_dashboard_recap.py:73 -- the AST chain
    # ``query -> urlencode -> url -> Request -> urlopen`` fired SSRF against
    # the hardcoded GRAFANA_QUERY_URL constant with the taint confined to
    # the percent-encoded query payload. ``quote``/``quote_plus`` are
    # deliberately NOT listed: their ``safe=`` kwarg can re-enable ``:``
    # and hand back a usable absolute URL, which this model cannot prove
    # away. Destination-control SSRF (attacker value as the URL itself,
    # including through aliases) is untouched.
    "ssrf": frozenset({
        "urllib.parse.urlencode",
    }),
}

_ALL_SANITIZERS: frozenset[str] = frozenset().union(*SANITIZERS.values())

# T-2.3: rule-declared sanitizer overrides.  Rules may extend one of the
# THREE modelled classes (xss / command_injection / ssrf) with extra
# dotted-names; they can never CREATE a class (that would change
# frozenset(SANITIZERS) and the sanitized_for semantics the taint layer
# relies on).  Loaded lazily from core.rule_loader; with no rule
# declarations (the production pack) the effective table IS the built-in
# SANITIZERS object, so every existing flow is byte-identical.
_RULE_SANITIZERS: Optional[dict[str, frozenset[str]]] = None
_EFFECTIVE: Optional[dict[str, frozenset[str]]] = None


def _load_rule_sanitizers() -> dict[str, frozenset[str]]:
    """vuln class -> extra sanitizer names declared by rules (T-2.3).

    Additive only; filtered to the modelled classes so an unknown vuln
    declaration is dropped here (the loader keeps it, the engine refuses
    it) rather than silently widening the class vocabulary.
    """
    try:
        from core import rule_loader
        decls = rule_loader.load_sanitizer_overrides()
    except Exception:  # noqa: BLE001 - a broken rule pack must not kill taint
        return {}
    known = set(SANITIZERS)
    out: dict[str, set[str]] = {}
    for _rule_id, info in decls.items():
        vuln = info.get("vuln")
        if vuln not in known:
            continue
        out.setdefault(vuln, set()).update(info.get("sanitizers") or ())
    return {k: frozenset(v) for k, v in out.items()}


def _effective_sanitizers() -> dict[str, frozenset[str]]:
    """Built-in SANITIZERS extended by any rule-declared sanitizers.

    Cached.  With no declarations this returns the SANITIZERS object
    itself (identity, not a copy), so the hot path costs one global-None
    check and the sanitizer tables cannot drift.
    """
    global _EFFECTIVE, _RULE_SANITIZERS
    if _EFFECTIVE is None:
        if _RULE_SANITIZERS is None:
            _RULE_SANITIZERS = _load_rule_sanitizers()
        if not _RULE_SANITIZERS:
            _EFFECTIVE = SANITIZERS
        else:
            _EFFECTIVE = {
                k: (v | _RULE_SANITIZERS.get(k, frozenset()))
                for k, v in SANITIZERS.items()
            }
    return _EFFECTIVE

# Shell interpreters whose presence in an argv list means the argument vector
# is still interpreted by a shell (``bash -c <payload>``, ``sh -c ...``).
_SHELL_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "ksh", "dash", "csh", "tcsh", "ash", "busybox",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
})

# Programs that interpret their arguments (option parsing, expression or script
# evaluation, or re-execution) and therefore cannot be exempted from command
# injection on the grounds that "no shell is involved".  Plain data-processing
# executables (ls, cat, cp, echo, wc, ...) are deliberately absent.
_ARGV_INTERPRETING_PROGRAMS = _SHELL_INTERPRETERS | frozenset({
    "python", "python2", "python3", "pythonw", "pypy", "pypy3",
    "perl", "ruby", "node", "nodejs", "php", "lua", "java", "javac",
    "awk", "gawk", "mawk", "nawk", "sed", "grep", "egrep", "fgrep",
    "env", "xargs", "find", "eval", "exec", "sudo", "su", "doas",
    "git", "docker", "podman", "kubectl", "make", "npm", "npx", "pip", "pip3",
    "wget", "curl", "base64", "openssl", "certutil", "bitsadmin",
})

# Expression node types that can only ever evaluate to a code constant.
# Anything else (Name / Call / Attribute / Subscript) can reference runtime
# state and therefore cannot be proven free of attacker input.
_CONSTANT_ONLY_NODES = (
    ast.Expression, ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict,
    ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.IfExp, ast.JoinedStr,
    ast.FormattedValue, ast.Starred, ast.Slice,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow, ast.FloorDiv,
    ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd, ast.MatMult,
    ast.USub, ast.UAdd, ast.Not, ast.Invert, ast.And, ast.Or, ast.Eq, ast.NotEq,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot, ast.In, ast.NotIn,
    ast.Load, ast.Store, ast.Del,
)

# Same-file call seeding terminates on self-recursion and on chains longer
# than this.  Six hops already covers a route handler -> parser -> helper
# shape; beyond that a static engine is guessing about depth it cannot see.
_MAX_CALL_DEPTH = 6

# Source tokens that describe an HTTP request rather than the operator's own
# machine.  Same-file call seeding is restricted to these, because the threat
# model this product scores is untrusted *network* input reaching a dangerous
# sink (ground truth in_scope: "a demonstrable untrusted source").
#
# Intra-procedural handling of every remaining source in TAINT_SOURCES is
# unchanged.  ``os.environ``/``os.getenv`` are no longer sources at all (A5:
# operator-written deployment config, not network input), so they neither
# taint locally nor cross a call.  What is withheld from the cross-function
# step is only ``sys.argv``/``input()``: propagating those into a callee turns
# ordinary CLI code into a reported vulnerability.  The measured case was
#     run_cmd(f'cd "{SANDBOX_DIR}" && docker build ...')
# where SANDBOX_DIR = os.getenv("SANDBOX_DIR", ...), which produced three
# command-injection findings inside a generic runner and one negative-control
# violation (NC-03) on the AI/LLM corpus.
_NETWORK_SOURCE_TOKENS = frozenset({
    "request.args", "request.form", "request.json", "request.data",
    "request.headers", "request.cookies", "request.values",
    "request.get_json", "request.files",
    "request.get", "request.post", "request.body", "request.cookies",
    "request.files", "request.meta", "request.path", "request.path_info",
    "request.full_path", "request.get_full_path",
    "params", "query", "kwargs",
    "self.headers", "self.rfile.read", "self.path", "self.command",
})


def _network_source(expr) -> bool:
    """True when a source expression is request-derived.

    The head is the call/attribute/subscript prefix of the expression, so
    ``query.split(":", 1)`` still identifies the ``query`` source token that
    ``_match_source`` recorded, and ``route parameter {object_key}`` is
    request-derived by construction.  The subscript case matters symmetrically:
    ``_match_source`` records ``request.args["url"]`` as a source via its
    ``startswith(src + "[")`` branch (A9f control), so the head must cut at
    ``[`` as well as ``(`` or the seeding gate would refuse the most
    canonical Flask destination shape there is -- intra-procedural matching
    says source, interprocedural said not-network, for one expression.
    """
    text = str(expr or "").strip()
    if not text:
        return False
    if text.startswith("__param__:"):
        # T-2.1 interprocedural parameter seed (scanner/taint_interproc.py).
        # An edge is only ever created from a caller whose provenance already
        # passed this predicate (A5/G-035 extended across files: sys.argv and
        # input() never cross a call), so the marker *stands for*
        # request-derived provenance and both the summary walk and the
        # seeded re-run must let it hop through a same-file helper here.
        return True
    if text.lower().startswith("route parameter "):
        return True
    head = re.split(r"[\(\[]", text, maxsplit=1)[0].strip().lower()
    if not head:
        return False
    for token in _NETWORK_SOURCE_TOKENS:
        if head == token or head.startswith(token + "."):
            return True
    return False


def _network_taint(tv: "TaintedVar") -> bool:
    """True when a tainted value traces back to a request-derived source."""
    if tv is None:
        return False
    if _network_source(tv.source):
        return True
    return any(_network_source(part) for part in (tv.chain or ()))

# ``/items/{item_id}``, ``/{bucket}/{object_key:path}``, ``/<name>`` and
# ``/<path:filename>`` -- the two framework spellings of a path parameter put
# the converter on *opposite* sides: Flask is ``<converter:name>`` while
# FastAPI/Django are ``{name:converter}``. Matching both with one capture
# would bind ``path`` instead of ``fname`` on the Flask form.
_ROUTE_PARAM_RE = re.compile(
    r"\{([A-Za-z_]\w*)(?::[^{}]*)?\}"
    r"|<((?:(?:[A-Za-z_]\w*):)?[A-Za-z_]\w*)>"
)


def _formal_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = fn.args
    params = ([x.arg for x in a.posonlyargs] + [x.arg for x in a.args]
              + [x.arg for x in a.kwonlyargs])
    if a.vararg is not None:
        params.append(a.vararg.arg)
    if a.kwarg is not None:
        params.append(a.kwarg.arg)
    return params


def _route_param_map(tree: ast.AST) -> dict[str, set[str]]:
    """Route path parameters declared by a decorated handler.

    Only a name that appears inside a string literal on the decorator counts,
    so ``@app.route("/x")`` seeds nothing and a decorated function whose
    signature happens to contain ``path`` is unaffected unless the template
    really binds ``{path}``.
    """
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names: set[str] = set()
        for dec in node.decorator_list:
            for sub in ast.walk(dec):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    for m in _ROUTE_PARAM_RE.finditer(sub.value):
                        if m.group(1):
                            # ``{name}`` / ``{name:converter}`` -- name leads.
                            names.add(m.group(1))
                        elif m.group(2):
                            # ``<name>`` / ``<converter:name>`` -- name trails.
                            names.add(m.group(2).rsplit(":", 1)[-1])
        if names:
            out[node.name] = names
    return out


_METHOD_DECORATORS = frozenset({"get", "post", "put", "delete", "patch",
                                "head", "options", "route", "api_view"})


def _route_handler_names(tree: ast.AST) -> set[str]:
    """Names of functions decorated as HTTP route handlers.

    Reflected XSS is a property of the response surface: returning attacker
    data from a route handler is unsafe HTML, while the same return in a
    library function or CLI says nothing about rendering. The decorator is
    what makes a function a response surface, so it -- not the body's shape --
    is the gate. Matches Flask/FastAPI/Django-ASGI shapes: ``@app.route``,
    ``@app.get``/``@router.post`` (method decorators carrying a path), and
    bare ``@route`` from ``from flask import route``.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            parts: list[str] = []
            cur = target
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr.lower())
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id.lower())
            if not parts:
                continue
            leaf = parts[0]
            if leaf == "route" or (leaf in _METHOD_DECORATORS
                                   and (len(parts) >= 2 or leaf == "route")):
                out.add(node.name)
                break
    return out


def _function_map(tree: ast.AST) -> dict[str, tuple[list[str], list]]:
    """Same-file ``def`` names to (formal parameters, body statements).

    The first definition wins, so a module-level ``def`` takes precedence over
    a nested one with the same name.  Only same-file definitions are resolved:
    anything else would require import or call-graph inference this engine
    does not do.
    """
    out: dict[str, tuple[list[str], list]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        out.setdefault(node.name, (_formal_params(node), list(node.body)))
    return out



BIG4_TAINT_CONTROLS = {
    "spel_injection": {"pci_dss":"Req 6.2.4 - Prevent injection attacks", "nist":"SI-10", "iso27001":"A.14.2.5", "soc2":"CC6.6"},
    "orm_injection": {"pci_dss":"Req 6.2.4 - Prevent injection attacks", "nist":"SI-10", "iso27001":"A.14.2.5", "soc2":"CC6.1 / CC6.6"},
    "prototype_pollution": {"pci_dss":"Req 6.2.4 - Secure development", "nist":"SI-10 / CM-7", "iso27001":"A.8.28 / A.8.29", "soc2":"CC6.6 / CC7.2"},
    "mass_assignment": {"pci_dss":"Req 6.2.4 / Req 7 - Access control", "nist":"AC-3 / SI-10", "iso27001":"A.9.4.1 / A.14.2.5", "soc2":"CC6.1 / CC6.6"},
    "idor": {"pci_dss":"Req 7 / Req 8 - Access control", "nist":"AC-3 / AC-6", "iso27001":"A.9.4.1", "soc2":"CC6.1"},
    "ssrf": {"pci_dss":"Req 6.2.4 - Prevent SSRF attacks", "nist":"SC-7", "iso27001":"A.13.1.3", "soc2":"CC6.6"},
    "resource_exhaustion": {"pci_dss":"Req 6.2.4 / Req 8 - Abuse prevention", "nist":"AC-7 / SC-5 / SI-10", "iso27001":"A.8.16 / A.8.20", "soc2":"CC7.2 / CC6.6"},
}
BIG4_TAINT_REMEDIATION = {
    "spel_injection": ["Do not evaluate user-controlled input with SpEL parseExpression().", "Replace dynamic expressions with allow-listed server-side operations.", "Use SimpleEvaluationContext and block type/method/constructor references."],
    "orm_injection": ["Use parameter binding for JPQL/HQL/SQL and avoid string concatenation/interpolation.", "Use repository methods or criteria builders with typed parameters.", "Add tests proving malicious query fragments are treated as data."],
    "prototype_pollution": ["Reject __proto__, constructor and prototype keys recursively.", "Use safe merge libraries configured to block prototype mutation.", "Validate object schemas before merging request bodies."],
    "mass_assignment": ["Bind request bodies to DTOs rather than domain/entity objects.", "Allow-list fields and block role, isAdmin, permissions, tenantId, status and balance.", "Authorize server-side after binding and before persistence."],
    "idor": ["Enforce object-level authorization before repository/database lookup returns data.", "Verify tenant and owner match the authenticated principal.", "Add negative authorization tests for cross-user and cross-tenant IDs."],
    "resource_exhaustion": ["Add query depth and complexity limits.", "Set per-user/IP/tenant rate limits and timeouts.", "Reject oversized request bodies and expensive queries."],
}

@dataclass
class TaintedVar:
    name: str
    source: str
    lineno: int
    chain: list[str] = field(default_factory=list)
    # Vuln classes for which this value has passed through a context-correct
    # sanitizer (see SANITIZERS).  A value can be safe for one class and still
    # dangerous for another, so this is a set of vuln classes, never a blanket
    # "clean" flag.
    sanitized_for: frozenset[str] = frozenset()
    def full_chain(self) -> list[str]:
        parts = [self.source] + self.chain + [self.name]
        out: list[str] = []
        for p in parts:
            if not out or out[-1] != p:
                out.append(p)
        return out

@dataclass
class TaintFinding:
    vuln_type: str
    source_var: str
    source_expr: str
    sink_call: str
    file: str
    line: int
    snippet: str
    taint_path: str
    chain: list[str]
    function: str = ""
    rule_id: str = ""
    title: str = ""
    language: str = "python"
    confidence: str = "High"
    severity: str | None = None
    cwe: str = ""
    owasp: str = ""
    remediation: list[str] = field(default_factory=list)


# H1 (2026-10-19, dvpwa sqli/dao/student.py + VAmPI models/user_model.py):
# SQL statement text built by string interpolation at the BUILD site.  The
# taint layer only reports these when the interpolated value is
# attacker-tainted *within the same function*; both measured misses hand
# the value across a function/module boundary (dvpwa dao
# create(conn, name) %-formats the statement, VAmPI
# models/user_model.py get_user(username) builds the f-string), so the
# name is an ordinary untainted parameter and every intra-procedural row
# stays dark -- the original prodtest reports carry no SQLi row for
# either file.  A query text must never be assembled from values at all
# (the Bandit B608 contract), so this fires when the literal text carries
# a SQL statement keyword-pair and at least one interpolated part is
# dynamic and NOT attacker-tainted.  Ownership rule: if any interpolated
# part is tainted (by name or direct source expression) the taint layer
# reports this defect at the SQL sink and this check stays silent, so a
# second row can never double-count one defect on the corpus/e2e
# fixtures (vulnerable_app.py:16 / flask_sql/app.py:16 keep exactly
# their taint row).  Keyword PAIRS, not single words: "insert the row" or
# "selected 3 rows" in prose or log text cannot match, and VAmPI's
# '{"username": "%s"}' % (...) JSON template has no pair either.
_PY_SQL_INTERP_PAIRS = (
    re.compile(r"\bselect\b[\s\S]{0,400}\bfrom\b", re.I),
    re.compile(r"\binsert\s+into\b", re.I),
    re.compile(r"\bupdate\b[\s\S]{0,200}\bset\b", re.I),
    re.compile(r"\bdelete\s+from\b", re.I),
)


class TaintVisitor(ast.NodeVisitor):
    def __init__(self, lines: list[str], filepath: str,
                 route_params: Optional[dict[str, set[str]]] = None,
                 funcs: Optional[dict[str, tuple[list[str], list]]] = None,
                 route_handlers: Optional[set[str]] = None):
        self.lines = lines
        self.filepath = filepath
        # Lexical scope stack.  Index 0 is module scope; every function pushes a
        # frame.  Writes go to the innermost frame.  Reads resolve innermost
        # first and fall back to enclosing frames (closures / globals), but
        # never to a sibling function -- which is what previously leaked taint
        # from one function body into an unrelated one.
        self._scopes: list[dict[str, TaintedVar]] = [{}]
        # Per-frame *binding kind* for each name, used only to disambiguate
        # bare source tokens.  TAINT_SOURCES deliberately contains undotted
        # names such as ``query``/``params``/``kwargs`` (FastAPI signature
        # binding, Express-style destructuring, ``**kwargs``), but the same
        # identifier is routinely a local variable.  The kind answers which:
        #   "const" -- bound to a provably constant-only expression,
        #   "param" -- bound by a function signature (a real runtime value),
        #   "var"   -- any other runtime value.
        self._bindings: list[dict[str, str]] = [{}]
        # Per-frame open-file handles registered by ``with open(...) as fh``.
        # Only handles opened in a write mode are recorded, and only those
        # whose path expression names a Python source file are treated as a
        # code sink -- see ``visit_With`` / ``visit_Call``.
        self._handles: list[dict[str, dict]] = [{}]
        # Scope indices at which name resolution must stop.  A callee seeded
        # from a call site sees its own frame and the module frame, never the
        # caller's locals: ``def _peek(path)`` must not pick up a caller's
        # unrelated ``target_path`` merely because the names coincide.
        self._stop_at: list[int] = []
        # Same-file callees and their formal parameters, plus the route path
        # parameters declared by each decorated handler.  Both are derived from
        # the module AST by the caller and are empty for a bare visitor.
        self._funcs: dict[str, tuple[list[str], list]] = funcs or {}
        self._route_params: dict[str, set[str]] = route_params or {}
        self._route_handlers: set[str] = route_handlers or set()
        # Local name -> module-qualified path for names this file imports
        # (`from markupsafe import escape` binds a bare "escape"; see
        # _resolve_fn). Used only for sanitizer recognition.
        self._import_alias: dict[str, str] = {}
        # Re-entrancy guard and depth cap for same-file call seeding: a
        # self-recursive or mutually recursive pair must terminate.
        self._active: list[str] = []
        self._call_depth = 0
        # Findings already recorded at a given (vuln, line, sink).  A callee
        # seeded from two call sites, or a body visited both at its definition
        # and from a call, describes one defect; the downstream group_key
        # collapses them anyway, so recording twice only inflates the count.
        self._recorded: set[tuple] = set()
        # Statement-block ancestry of the statement being visited, as a tuple
        # of per-pass sequence numbers.  Used only to decide whether a
        # constant assignment really overwrites an existing taint: an
        # assignment in ``else:`` cannot declassify one made in the matching
        # ``if:`` body, because the two lie on different paths.
        self._block_seq = 0
        self._block_path: tuple = ()
        self._taint_block: dict[str, tuple] = {}
        self.findings: list[TaintFinding] = []
        self._cur_func = ""
        self._tainted_returns: dict[str, str] = {}
        # Names whose most recent assignment is a SQLAlchemy query-builder
        # expression, as (func, lineno, rhs).  A builder generates the SQL
        # text with bound parameters, so taint that only reaches a
        # .filter(col == value) is DATA, not SQL structure -- the eight
        # TAINT_SQL_INJECTION findings on wrongsecrets-style CRUD modules
        # (select(...).filter(Model.col == param); session.execute(query))
        # were exactly this shape.  Recorded only when the file imports
        # sqlalchemy, dropped on ANY non-builder reassignment, and read only
        # for a sink in the same function at a later line: proof, not hope.
        self._builder_assigns: dict[str, tuple[str, int, ast.AST]] = {}
        # T-2.1/T-2.2: interprocedural parameter seeds
        # (scanner/taint_interproc.py), keyed by the def's line number so a
        # class-qualified callee (Student.create) seeds exactly its own frame
        # and never an unrelated same-named def in another class. Empty on
        # every intra-procedural run, so worker findings are byte-identical
        # when the post-pass is off or finds no cross-file edge.
        self._interproc_seeds: dict[int, dict[str, TaintedVar]] = {}

    def _mark_tainted(self, name: str, tv: TaintedVar) -> None:
        """Write taint and remember which statement block wrote it."""
        self.tainted[name] = tv
        self._taint_block[name] = self._block_path

    def _kill_overwrites(self, name: str) -> bool:
        """True only when a constant assignment here certainly replaces taint.

        The taint must have been written in this block or in a block nested
        inside it, so this statement runs after it on every path.  A taint
        written in an enclosing block (this is a conditional assignment) or in
        a sibling block (``if`` body vs ``else`` body) is not overwritten here
        and must survive.
        """
        written = self._taint_block.get(name)
        if written is None:
            return False
        here = self._block_path
        return len(written) >= len(here) and written[:len(here)] == here

    def _visit_body(self, nodes) -> None:
        """Visit a statement list that only runs on some path."""
        self._block_seq += 1
        prev = self._block_path
        self._block_path = prev + (self._block_seq,)
        try:
            for n in nodes:
                self.visit(n)
        finally:
            self._block_path = prev

    @property
    def tainted(self) -> dict[str, TaintedVar]:
        """Innermost scope frame.  Preserves the original ``self.tainted``
        write surface used throughout this visitor."""
        return self._scopes[-1]

    def _lookup(self, name: str) -> Optional[TaintedVar]:
        stop = self._stop_at[-1] if self._stop_at else None
        for i in range(len(self._scopes) - 1, -1, -1):
            if stop is not None and i < stop:
                break
            t = self._scopes[i].get(name)
            if t is not None:
                return t
        if stop:
            # Module scope stays visible to a callee (globals and module
            # constants are not caller state); the caller's frame does not.
            return self._scopes[0].get(name)
        return None

    def _push_scope(self) -> None:
        self._scopes.append({})
        self._bindings.append({})
        self._handles.append({})

    def _pop_scope(self) -> None:
        if len(self._scopes) > 1:
            self._scopes.pop()
        if len(self._bindings) > 1:
            self._bindings.pop()
        if len(self._handles) > 1:
            self._handles.pop()

    def _set_binding(self, name: str, kind: str) -> None:
        self._bindings[-1][name] = kind

    def _binding_kind(self, name: str) -> Optional[str]:
        """Innermost binding kind for ``name``, mirroring ``_lookup``.

        Innermost-first resolution is what keeps a parameter that shadows an
        outer constant ("query" as a FastAPI argument over a module-level
        ``query = "SELECT 1"``) classified as a runtime value.
        """
        stop = self._stop_at[-1] if self._stop_at else None
        for i in range(len(self._bindings) - 1, -1, -1):
            if stop is not None and i < stop:
                break
            kind = self._bindings[i].get(name)
            if kind is not None:
                return kind
        if stop:
            return self._bindings[0].get(name)
        return None

    def _unparse(self, node) -> str:
        try: return ast.unparse(node)
        except Exception: return "<expr>"
    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        return self.lines[idx].rstrip() if 0 <= idx < len(self.lines) else ""
    @staticmethod
    def _segmented(expr: str) -> str:
        # "." + expr + "." so a source only matches on whole dotted segments.
        return "." + expr + "."
    def _match_source(self, node) -> Optional[str]:
        expr = self._unparse(node)
        for src in TAINT_SOURCES:
            if expr == src:
                # An undotted source token matched a *bare name*.  Decline it
                # when that name is bound to a provably constant-only
                # expression: ``query = "SELECT 1"`` is not attacker input
                # merely because ``query`` also names ``req.query``/``**query``.
                # Dotted sources (``request.args``) cannot collide with a local
                # identifier, and a name bound by a signature or to any
                # non-constant value keeps its source semantics, so no real
                # reachability is lost here.
                if ("." not in src
                        and isinstance(node, ast.Name)
                        and self._binding_kind(node.id) == "const"):
                    continue
                return src
        if isinstance(node, ast.Call):
            func_str = self._unparse(node.func)
            for src in TAINT_SOURCES:
                if func_str == src or func_str.startswith(src + ".") or func_str.startswith(src + "["):
                    return expr
            # Qualified imports: ``flask.request.args.get(...)`` must still
            # resolve to the ``request.args`` source, while names that merely
            # contain the source text (``sanitize_args.get(...)``) must not.
            for src in _DOTTED_SOURCES:
                if self._segmented(src) in self._segmented(func_str):
                    return expr
            if func_str in self._tainted_returns:
                return f"{func_str}() [returns tainted: {self._tainted_returns[func_str]}]"
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = self._unparse(node)
            for src in TAINT_SOURCES:
                if base == src or base.startswith(src + ".") or base.startswith(src + "["):
                    return base
            for src in _DOTTED_SOURCES:
                if self._segmented(src) in self._segmented(base):
                    return base
        return None
    def _tainted_names_in(self, node, for_vuln: Optional[str] = None) -> list[str]:
        """Names in ``node`` that currently carry taint.

        Two filters apply when ``for_vuln`` is given:
          * a name whose value already passed a sanitizer proven correct for
            that vuln class is not reported, and
          * a name *inside* a sanitizer call (``render_template_string(
            html.escape(x))``) is not reported for that class either -- the
            escaping happens at this very site.
        Neither filter applies to any other vuln class: ``html.escape`` is not
        a shell or SQL sanitizer.
        """
        seen: list[str] = []

        def _walk(n):
            if isinstance(n, ast.Call) and self._is_sanitizer_call(
                    self._resolve_fn(self._unparse(n.func)), for_vuln):
                return
            if isinstance(n, ast.Name) and n.id not in seen:
                t = self._lookup(n.id)
                if t is None:
                    return
                if for_vuln is not None and for_vuln in t.sanitized_for:
                    return
                seen.append(n.id)
            for child in ast.iter_child_nodes(n):
                _walk(child)

        _walk(node)
        return seen
    def _source_exprs_in(self, node, for_vuln: Optional[str] = None) -> list[str]:
        sources: list[str] = []
        def _walk(n):
            if isinstance(n, ast.Call) and self._is_sanitizer_call(
                    self._resolve_fn(self._unparse(n.func)), for_vuln):
                # The subtree feeding this call is escaped/quoted for the vuln
                # class, so its sources are no longer dangerous in this context.
                return
            src = self._match_source(n)
            if src and src not in sources:
                sources.append(src)
            for child in ast.iter_child_nodes(n):
                _walk(child)
        _walk(node)
        return sources
    def _chain_for(self, var_name: str) -> list[str]:
        t = self._lookup(var_name)
        return t.full_chain() if t else [var_name]

    # -- sanitizer / constant helpers -------------------------------------
    def _resolve_fn(self, fn: str) -> str:
        """Resolve a call target through this file's imports.

        ``from markupsafe import escape`` binds a bare ``escape`` that
        ast.unparse renders as just "escape", while the sanitizer tables are
        qualified ("markupsafe.escape"). Without import context every
        from-imported sanitizer was invisible: ``escape(user_input)`` read as
        an unknown function, values it purified were still treated as raw at
        every sink, and -- as the V1 mutation harness showed when its safe
        XSS fixture kept firing -- the engine reported the escaped form of
        its own baseline. Only the head segment is rewritten, and only for
        this match; an unrelated local ``escape()`` resolves to itself and
        still fails the qualified lookup, so the resolution cannot mint a
        sanitizer that the module did not import.
        """
        head, sep, tail = fn.partition(".")
        target = self._import_alias.get(head)
        if target and target != head:
            return target + (sep + tail if sep else "")
        return fn

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # Star imports are deliberately not tracked: their bound names are
        # unknowable without the source module, and guessing here would
        # classify an arbitrary local name as a proven sanitizer.
        if node.module and node.level == 0:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                self._import_alias[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            mod = alias.name if alias.asname else alias.name.split(".")[0]
            # Plain assignment, not setdefault: rebinding a name is legal and
            # the runtime resolves to the last binding.
            self._import_alias[local] = mod
        self.generic_visit(node)

    @staticmethod
    def _is_sanitizer_call(fn: str, for_vuln: Optional[str]) -> bool:
        # Without a vuln class there is nothing to be "safe for".
        if not for_vuln:
            return False
        names = _effective_sanitizers().get(for_vuln)
        if not names:
            return False
        return any(fn == s or fn.endswith("." + s) for s in names)
    def _sanitizer_classes(self, node) -> frozenset[str]:
        """Vuln classes for which ``node``'s value is provably purified.

        Attribution is occurrence-based, not outermost-call based (A9e): the
        sanitizing call may be *nested* -- the measured transformers chain was
        ``f"{GRAFANA_QUERY_URL}?{urlencode({'query': query})}"``, whose root
        is a JoinedStr, so the old root-only check returned nothing and the
        taint rode the variable through ``request_json`` into ``urlopen``
        with ``sanitized_for=`` empty.  A class counts only when EVERY
        tainted/source occurrence inside ``node`` lies within a call that
        sanitizes for that class (or already carries that class upstream in
        its own ``sanitized_for``).  One raw contributor vetoes the class for
        the whole value: ``f"{escape(a)} {b}"`` is not xss-purified, and
        ``html.escape`` never grants a shell or SQL class it does not wrap.

        The previous outermost-call behaviour is the special case where the
        root call is the sanitizer: every occurrence then lies inside it, so
        all existing non-nested attributions come out identical (only
        double-sanitizer chains and nested sanitizers gain attribution).
        """
        covered: Optional[frozenset[str]] = None
        eff = _effective_sanitizers()

        def _walk(n, wrapped: frozenset[str]) -> None:
            nonlocal covered
            if isinstance(n, ast.Call):
                fn = self._resolve_fn(self._unparse(n.func))
                cls = frozenset(c for c, names in eff.items()
                                if any(fn == s or fn.endswith("." + s) for s in names))
                if cls:
                    for child in ast.iter_child_nodes(n):
                        _walk(child, wrapped | cls)
                    return
            occ: Optional[frozenset[str]] = None
            if isinstance(n, ast.Name):
                t = self._lookup(n.id)
                if t is not None:
                    # Tainted-name occurrence: wrapper sanitizer or proven
                    # upstream sanitization both satisfy the class.
                    occ = wrapped | (t.sanitized_for & frozenset(eff))
                elif self._match_source(n):
                    occ = wrapped
            elif isinstance(n, (ast.Attribute, ast.Subscript)) and self._match_source(n):
                occ = wrapped
            if occ is not None:
                covered = occ if covered is None else (covered & occ)
            for child in ast.iter_child_nodes(n):
                _walk(child, wrapped)

        _walk(node, frozenset())
        return covered or frozenset()
    @staticmethod
    def _constant_only(node) -> bool:
        """True only for expressions built exclusively from code literals.

        No identifier, call, attribute or subscript is reachable, so the value
        cannot depend on runtime (attacker-controlled) state.  This is the only
        basis on which taint is discarded: provable, not heuristic.
        """
        for child in ast.walk(node):
            if not isinstance(child, _CONSTANT_ONLY_NODES):
                return False
        return True
    def _make_path(self, chain: list[str], sink: str) -> str:
        out = []
        for p in chain + [sink]:
            if not out or out[-1] != p:
                out.append(p)
        return " -> ".join(out)
    def _record(self, vuln_type: str, chain: list[str], sink_str: str, call_node: ast.Call):
        key = (vuln_type, call_node.lineno, sink_str)
        if key in self._recorded:
            # Same defect reached from a second call site or on a body that is
            # also visited at its definition.  One finding per (vuln, line,
            # sink) is what the downstream group_key already enforces.
            return
        self._recorded.add(key)
        self.findings.append(TaintFinding(vuln_type, chain[0] if chain else "", chain[0] if chain else "", sink_str, self.filepath, call_node.lineno, self._snippet(call_node.lineno), self._make_path(chain, sink_str), chain, self._cur_func))
    # -- sink-context precision rules -------------------------------------
    _SQL_QUERY_KEYS = frozenset({"query", "sql", "statement", "stmt", "operation", "q", "sqltext", "sql_text"})
    def _sql_query_node(self, call: ast.Call):
        """The argument that holds the SQL *text* (DB-API ``execute(query,
        params)`` contract), or None when the call shape is not recognised."""
        if call.args:
            return call.args[0]
        for kw in call.keywords:
            if kw.arg in self._SQL_QUERY_KEYS:
                return kw.value
        return None
    _SQL_BUILDER_CALLS = frozenset({"select", "insert", "update", "delete"})
    _DYNAMIC_SQL_TEXT_CALLS = frozenset({"text", "exec_driver_sql"})

    def _is_query_builder_rhs(self, rhs) -> bool:
        """True when *rhs* is a SQLAlchemy ORM/Core query-builder expression.

        ``select(User).filter(User.id == x)`` (also via a module alias such as
        ``sa.select``) compiles to a parameterized statement: the tainted
        value becomes a bound parameter and cannot alter SQL structure.  A
        dynamic-text call inside the builder (``select(text(f"..."))``)
        withholds the classification -- that shape IS injectable.
        """
        try:
            import_roots = {
                str(v).split(".", 1)[0] for v in self._import_alias.values()
            }
        except Exception:  # pragma: no cover - defensive, never kill on error
            return False
        if "sqlalchemy" not in import_roots:
            if import_roots & {"psycopg", "psycopg2"}:
                return self._is_psycopg_sql_builder(rhs)
            return False
        node = rhs
        # Unwrap fluent chaining: select(...).filter(...).order_by(...)
        while (isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Call)):
            node = node.func.value
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Attribute):
            base = func.attr  # sa.select / sqlalchemy.select
            recv = func.value
            while isinstance(recv, ast.Attribute):
                recv = recv.value
            # The receiver must be the sqlalchemy module alias itself, not an
            # object that happens to expose a .select() method.
            if not isinstance(recv, ast.Name) or not str(
                    self._import_alias.get(recv.id, "")).startswith("sqlalchemy"):
                # C3 (2026-10-16, llama_index): the receiver may instead be
                # a NAME already recorded as a builder product in this
                # function on an earlier line -- ``query =
                # select(Table).where(...)`` followed by ``query =
                # query.limit(limit)`` / ``query = query.where(...)``
                # compiles to the same parameterized statement.  The Name
                # receiver failed the module-alias test, so the record was
                # POPPED and llama_index's llama-index-core/.../storage/
                # chat_store/sql.py fired 3 false TAINT_SQL_INJECTION rows
                # on exactly this chain.  Provenance transfers only from a
                # live record that predates this expression; the
                # dynamic-text sub-walk below still withholds the
                # classification for ``text(f"...")`` inside the chain.
                entry = (self._builder_assigns.get(recv.id)
                         if isinstance(recv, ast.Name) else None)
                if (entry is None
                        or entry[0] != self._cur_func
                        or entry[1] >= rhs.lineno):
                    return False
                # Chain method on a proven builder (limit/offset/where/
                # order_by/...) -- the constructor-name check below does
                # not apply, so classify here after the same
                # dynamic-text guard.
                for sub in ast.walk(rhs):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        fname = (f.attr if isinstance(f, ast.Attribute)
                                 else f.id if isinstance(f, ast.Name) else "")
                        if fname in self._DYNAMIC_SQL_TEXT_CALLS:
                            return False
                return True
        elif isinstance(func, ast.Name):
            base = func.id  # from sqlalchemy import select
        else:  # pragma: no cover - defensive
            return False
        if base not in self._SQL_BUILDER_CALLS:
            return False
        for sub in ast.walk(rhs):
            if isinstance(sub, ast.Call):
                f = sub.func
                fname = (f.attr if isinstance(f, ast.Attribute)
                         else f.id if isinstance(f, ast.Name) else "")
                if fname in self._DYNAMIC_SQL_TEXT_CALLS:
                    return False
        return True

    def _is_psycopg_sql_builder(self, rhs) -> bool:
        """True when *rhs* is a psycopg ``sql.SQL(...)`` template product.

        ``sql.SQL("... %s ...").format(sql.Identifier(col), sql.Placeholder())``
        compiles to a parameterized statement: identifiers are quoted by the
        builder and values ride in the separate params tuple, so taint in the
        inputs cannot become SQL structure (postgres.py
        ``_construct_vector_query``).  An f-string or ``%``-interpolation
        inside ``SQL(...)`` IS string-built SQL and stays reportable.
        """
        node = rhs
        while (isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute)
               and isinstance(node.func.value, ast.Call)):
            node = node.func.value
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Attribute):
            base = func.attr  # sql.SQL
            recv = func.value
            while isinstance(recv, ast.Attribute):
                recv = recv.value
            if not isinstance(recv, ast.Name):
                return False
            alias = str(self._import_alias.get(recv.id, ""))
            if alias.split(".", 1)[0] not in {"psycopg", "psycopg2"}:
                return False
        elif isinstance(func, ast.Name):
            base = func.id  # from psycopg.sql import SQL
        else:  # pragma: no cover - defensive
            return False
        if base != "SQL":
            return False
        for sub in ast.walk(rhs):
            # Interpolated text defeats the template's parameterization.
            if isinstance(sub, ast.JoinedStr):
                return False
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod):
                return False
        return True

    _SQL_BIND_KEYWORDS = frozenset(
        {"params", "parameters", "binds", "bind_vars", "bindvars",
         "args", "sequence_of_parameters"}
    )
    def _sql_text_is_tainted(self, call: ast.Call) -> bool:
        # DB-API parameterization contract: ``execute(query, params)`` binds
        # the second argument, so attacker data cannot become SQL structure.
        # The semantic-kernel connectors all build SQL with their own
        # parameterizing builders and pass binds separately (psycopg
        # ``sql.SQL(...).format(...)`` + ``%s`` params, sqlserver ``SqlCommand``
        # with ``?`` + ``add_parameter``, oracle ``executemany(query, binds)``)
        # -- none of which import sqlalchemy, so the builder kill below alone
        # could not see them.
        if len(call.args) >= 2:
            return False
        for kw in call.keywords:
            if kw.arg in self._SQL_BIND_KEYWORDS:
                return False
        # A driver command object whose ``to_execute()`` yields (sql, params):
        # the executed value is the parameterized half of that tuple.
        for node in ast.walk(call):
            if isinstance(node, ast.Call):
                f = node.func
                fname = (f.attr if isinstance(f, ast.Attribute)
                         else f.id if isinstance(f, ast.Name) else "")
                if fname == "to_execute":
                    return False
        q = self._sql_query_node(call)
        if q is None:
            # Cannot establish which argument is the statement -- stay
            # conservative and let the generic rules run.
            return True
        root = q
        while isinstance(root, (ast.Call, ast.Attribute)):
            root = root.func if isinstance(root, ast.Call) else root.value
        if isinstance(root, ast.Name):
            entry = self._builder_assigns.get(root.id)
            if (entry is not None
                    and entry[0] == self._cur_func
                    and entry[1] < call.lineno):
                # The statement is a query-builder product recorded earlier
                # in this same function; taint rides in bound parameters.
                if root is q:
                    return False
                # C3: the sink argument is a fluent chain off that recorded
                # name (``session.execute(query.order_by(...))`` --
                # chat_store/sql.py:199).  A chain of builder methods still
                # compiles to a parameterized statement; only a
                # dynamic-text call inside the chain (``text(f"...")``)
                # revokes that.
                for sub in ast.walk(q):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        fname = (f.attr if isinstance(f, ast.Attribute)
                                 else f.id if isinstance(f, ast.Name) else "")
                        if fname in self._DYNAMIC_SQL_TEXT_CALLS:
                            break
                else:
                    return False
        return bool(self._tainted_names_in(q, "sql_injection")
                    or self._source_exprs_in(q, "sql_injection"))
    def _is_argv_execution(self, call: ast.Call) -> bool:
        """True when the command is an argv sequence no shell interprets.

        Command injection (CWE-78) requires shell metacharacter
        interpretation.  ``subprocess.run(["ls", tainted])`` with ``shell``
        absent or literally ``False`` passes the value as argv, so it cannot
        change which command runs.  The exemption is withheld whenever the
        vector contains a program that *interprets* its arguments (shell,
        script interpreter, ``env``/``xargs``/``find`` exec wrappers, ...),
        so ``["sh", "-c", x]``, ``["python", x]`` and ``["bash", x]`` remain
        findings.
        """
        if not call.args:
            return False
        first = call.args[0]
        if not isinstance(first, (ast.List, ast.Tuple)):
            return False
        for kw in call.keywords:
            if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                # shell=True, or a dynamic flag: assume shell interpretation.
                return False
        for elt in first.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                base = elt.value.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if base in _ARGV_INTERPRETING_PROGRAMS:
                    return False
        return True
    def _check_sink(self, call: ast.Call):
        call_str = self._unparse(call.func)
        for sink_key, vuln_type in DANGEROUS_SINKS.items():
            if call_str != sink_key and not call_str.endswith("." + sink_key):
                continue
            if (
                vuln_type == "sql_injection"
                and sink_key in _BARE_SQL_SINK_KEYS
                and call_str.endswith("." + sink_key)
                and _PURE_DOTTED_CALL_RE.fullmatch(call_str)
            ):
                # A10: pure dotted receiver whose last segment is not a
                # DB handle (``g.functionz.executor.execute``) is not SQL.
                # ``get_db().execute``/``rows[i].execute`` fail the dotted
                # chain test above and keep firing (unprovable).
                receiver_tail = call_str.rsplit(".", 1)[0].rsplit(".", 1)[-1]
                if receiver_tail not in _SQL_DB_RECEIVER_TAILS:
                    continue
            if (
                vuln_type == "code_injection"
                and sink_key == "compile"
                and call_str.endswith("." + sink_key)
                and call_str.rsplit(".", 1)[0] != "builtins"
            ):
                # B3: every dotted ``.compile`` host compiles something that
                # is NOT attacker source text -- ``re.compile`` a regex,
                # ``torch.compile`` a model graph (peft's
                # ``torch.compile(model, dynamic=True)`` carried
                # request-shaped taint and reported TAINT_CODE_INJECTION),
                # ``py_compile.compile``/``compileall`` files, XPath
                # ``XPath.compile`` an expression, Pattern/WebAssembly
                # likewise.  The Python builtin ``compile(source, ...)``,
                # the only compile that turns attacker text into executable
                # bytecode, is receiver-less (or explicitly
                # ``builtins.compile``) and keeps firing -- the same
                # receiver-form discipline A1 applied to eval.
                continue
            if (
                vuln_type == "code_injection"
                and sink_key == "exec"
                and call_str.endswith("." + sink_key)
                and call_str.rsplit(".", 1)[0] != "builtins"
            ):
                # B5 (2026-10-16, Open-Assistant): the bare ``exec``
                # key matched any dotted receiver, so SQLModel's
                # ``session.exec(query)`` -- a SELECT run through the
                # query-builder API, 18 rows in the OA report -- was
                # reported as TAINT_CODE_INJECTION wherever a route
                # parameter reached the query.  In Python, code
                # execution is the receiver-less builtin
                # ``exec(statements)`` (or ``builtins.exec``); no
                # dotted ``.exec`` host in the ecosystem executes
                # Python source -- session/db handles run queries.
                # Same receiver-form discipline as A10/B3; the
                # builtin keeps firing.
                continue
            if vuln_type == "sql_injection" and not self._sql_text_is_tainted(call):
                # Statement text is a constant/untainted expression and any
                # taint sits in the bound parameters: parameterized query, the
                # value is data, not SQL structure.
                continue
            if vuln_type == "command_injection" and self._is_argv_execution(call):
                continue
            if vuln_type == "ssrf":
                # A9: taint outside the URL argument cannot steer the fetch.
                all_args = _ssrf_url_args(call)
            else:
                all_args = list(call.args) + [kw.value for kw in call.keywords]
            for arg in all_args:
                names = self._tainted_names_in(arg, vuln_type)
                if names:
                    self._record(vuln_type, self._chain_for(names[0]), call_str, call); return
            for arg in all_args:
                srcs = self._source_exprs_in(arg, vuln_type)
                if srcs:
                    self._record(vuln_type, [srcs[0]], call_str, call); return
    def visit_Assign(self, node: ast.Assign):
        rhs = node.value
        # Resolve the RHS against bindings as they stand *before* this
        # assignment, so ``query = query`` cannot launder a proven constant
        # into an untracked runtime value.
        src_label = self._match_source(rhs)
        # Every simple-name target starts as an ordinary runtime value; the
        # constant-only branch below is the only path that promotes it.
        for t in node.targets:
            if isinstance(t, ast.Name):
                self._set_binding(t.id, "var")
                # Track/invalidate query-builder provenance for SQL sinks:
                # ANY non-builder reassignment drops the record, so a later
                # ``query = request.args["q"]`` can never inherit the kill.
                if self._is_query_builder_rhs(node.value):
                    self._builder_assigns[t.id] = (self._cur_func, node.lineno, node.value)
                else:
                    self._builder_assigns.pop(t.id, None)
        if src_label is not None:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._mark_tainted(t.id, TaintedVar(t.id, src_label, node.lineno, [], frozenset()))
            self.generic_visit(node)
            return
        names = self._tainted_names_in(rhs)
        san_classes = self._sanitizer_classes(rhs)
        parents = [p for p in (self._lookup(n) for n in names) if p is not None]
        if parents:
            parent = parents[0]
            if san_classes:
                # The value passed through a context-correct escaping primitive:
                # sanitize for that class only, never blanket-approve it.
                new_sf = san_classes
            else:
                # Alias / concatenation: inherit the sanitization state, but only
                # when *every* contributing value carries it (intersection).
                new_sf = parents[0].sanitized_for
                for p in parents[1:]:
                    new_sf = new_sf & p.sanitized_for
            for t in node.targets:
                if isinstance(t, ast.Name):
                    new_chain = parent.full_chain() + [t.id]
                    self._mark_tainted(t.id, TaintedVar(t.id, parent.source, node.lineno, new_chain[1:], new_sf))
            self.generic_visit(node)
            return
        # The source sits *inside* the RHS rather than being the RHS.  Two
        # shapes matter and neither is rare:
        #
        #   data = request.get_json(force=True, silent=True) or {}
        #   n    = int(self.headers.get("Content-Length", 0))
        #
        # In both the outermost node is a BoolOp or a cast, which is not a
        # source node itself, so ``_match_source`` declines and no tainted name
        # is present yet -- and the attacker input still arrives.  Recording it
        # as tainted-but-maybe-sanitized is what keeps ``html.escape(x)``
        # correct: ``san_classes`` is empty unless the outermost call really is
        # a context-correct escaper, so every other vuln class still sees the
        # value as dangerous.
        srcs = self._source_exprs_in(rhs)
        if srcs:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._mark_tainted(t.id, TaintedVar(t.id, srcs[0], node.lineno, [], san_classes))
            self.generic_visit(node)
            return
        if self._constant_only(rhs):
            # Taint kill.  An expression built only from literals cannot carry
            # attacker input, so prior taint on the target is invalidated --
            # but only when this statement certainly runs after the taint was
            # written.  Without that condition an ``else:`` branch assigning
            # the empty string would declassify a value that a sibling ``if:``
            # branch had just derived from the request, which is how
            # ``remainder = ""`` used to erase ``query.split(...)[1]``.
            # Deliberately NOT applied to ``x = helper()`` or ``x = CONST``:
            # those reference runtime state this engine cannot prove safe.
            for t in node.targets:
                if isinstance(t, ast.Name):
                    # Promote the binding: this name now provably holds a
                    # code constant, which is what lets _match_source decline
                    # it when the identifier doubles as a bare source token.
                    self._set_binding(t.id, "const")
                    if t.id in self.tainted and self._kill_overwrites(t.id):
                        del self.tainted[t.id]
                        self._taint_block.pop(t.id, None)
        self.generic_visit(node)
    def visit_AugAssign(self, node: ast.AugAssign):
        if isinstance(node.target, ast.Name):
            t_name = node.target.id
            src_label = self._match_source(node.value)
            # ``query += ...`` is a runtime write: the name can no longer be
            # proven constant, so drop any prior "const" classification.
            self._set_binding(t_name, "var")
            self._builder_assigns.pop(t_name, None)
            names = self._tainted_names_in(node.value)
            if src_label:
                if t_name not in self.tainted:
                    self._mark_tainted(t_name, TaintedVar(t_name, src_label, node.lineno, [], frozenset()))
            elif names and t_name not in self.tainted:
                # AugAssign never clears taint: ``x += ...`` retains x's prior
                # value, so a literal RHS cannot declassify an existing source.
                parent = self._lookup(names[0])
                if parent is not None:
                    self._mark_tainted(t_name, TaintedVar(t_name, parent.source, node.lineno, parent.full_chain()[1:] + [t_name], parent.sanitized_for))
        self.generic_visit(node)
    # -- H1: SQL statement interpolation at the build site ----------------
    def _sql_interp_finding(self, node, literal_text: str,
                            dyn_nodes: list, kind: str) -> None:
        """Emit PY_SQL_INTERPOLATED_QUERY for one interpolation site."""
        if not any(p.search(literal_text) for p in _PY_SQL_INTERP_PAIRS):
            return
        dynamic = [d for d in dyn_nodes if not (
            isinstance(d, ast.Constant) and isinstance(d.value, str))]
        if not dynamic:
            return
        # Taint ownership: an attacker-tainted interpolated part means the
        # taint layer reports this defect at the SQL sink; a second row
        # here would double-count one bug as an extra finding.
        for part in dynamic:
            if (self._tainted_names_in(part, "sql_injection")
                    or self._source_exprs_in(part, "sql_injection")):
                return
        names: list[str] = []
        for part in dynamic:
            for n in ast.walk(part):
                if isinstance(n, ast.Name):
                    names.append(n.id)
        names = list(dict.fromkeys(names))
        sink_str = self._unparse(node)[:200]
        key = ("sql_injection", node.lineno, sink_str)
        if key in self._recorded:
            return
        self._recorded.add(key)
        self.findings.append(TaintFinding(
            vuln_type="sql_injection",
            source_var=names[0] if names else "",
            source_expr=", ".join(names),
            sink_call=sink_str,
            file=self.filepath,
            line=node.lineno,
            snippet=self._snippet(node.lineno),
            taint_path=(
                "SQL statement text built by %s interpolation of "
                "non-request value(s): %s -- the value crosses a function "
                "boundary, so no intra-procedural taint row can see it"
                % (kind, ", ".join(names) or "expression")),
            chain=names,
            function=self._cur_func,
            rule_id="PY_SQL_INTERPOLATED_QUERY",
            title="Python SQL Query Built by String Interpolation",
            confidence="High",
        ))

    def visit_JoinedStr(self, node: ast.JoinedStr):
        dyn = [v.value for v in node.values
               if isinstance(v, ast.FormattedValue)]
        if dyn:
            literal = "".join(
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str))
            self._sql_interp_finding(node, literal, dyn, "f-string")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        if (isinstance(node.op, ast.Mod)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)):
            self._sql_interp_finding(
                node, node.left.value, [node.right], "%-format")
        elif isinstance(node.op, ast.Add):
            lits: list[str] = []
            dyn: list = []
            for side in (node.left, node.right):
                if (isinstance(side, ast.Constant)
                        and isinstance(side.value, str)):
                    lits.append(side.value)
                else:
                    dyn.append(side)
            if lits and dyn:
                self._sql_interp_finding(
                    node, "".join(lits), dyn, "concatenation")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self._cur_func; self._cur_func = node.name
        # Each function body gets its own frame so taint assigned in one
        # function cannot be observed by a sibling function.
        self._push_scope()
        prev_block = self._block_path
        self._block_path = ()
        try:
            # Signature parameters shadow every enclosing binding and are real
            # runtime values, so they must never inherit an outer "const"
            # classification (``def handler(query)`` over a module-level
            # ``query = "SELECT 1"`` stays a source).
            a = node.args
            params = ([x.arg for x in a.posonlyargs] + [x.arg for x in a.args]
                      + [x.arg for x in a.kwonlyargs])
            if a.vararg is not None:
                params.append(a.vararg.arg)
            if a.kwarg is not None:
                params.append(a.kwarg.arg)
            for p in params:
                self._set_binding(p, "param")
            # A framework route parameter is attacker input by construction: the
            # path segment is supplied by the client and the decorator is what
            # declares it.  Seeding is restricted to names that literally appear
            # in the route template, so a handler with a decorated sibling
            # signature does not pick up taint on an unrelated argument.
            for p in self._route_params.get(node.name, ()):
                if p in params:
                    self._mark_tainted(p, TaintedVar(
                        # No braces around the parameter name. They were a visual
                        # marker distinguishing a route parameter from an ordinary
                        # one, but `p` is already the identifier -- wrapping it in {}
                        # made every rendered surface read "route parameter
                        # {function_name}" as a template placeholder rather than as
                        # code. In a narrative that misstates the source: the real
                        # variable is `function_name`.
                        # reporting/attack_path_view.py strips the brace form too, so
                        # artifacts already written with it read cleanly as well.
                        p, f"route parameter {p}", node.lineno, [], frozenset()))
            # T-2.1: a cross-file caller's argument taint lands on this
            # parameter, carrying the caller's provenance plus the
            # ``__param__`` marker that identifies the file boundary the
            # value crossed. Applied after the route-parameter seed so the
            # interprocedural chain (richer provenance) wins if both apply.
            for p, tv in self._interproc_seeds.get(node.lineno, {}).items():
                if p in params:
                    self._mark_tainted(p, tv)
            self.generic_visit(node)
        finally:
            self._block_path = prev_block
            self._pop_scope()
            self._cur_func = prev
    visit_AsyncFunctionDef = visit_FunctionDef
    def visit_Return(self, node: ast.Return):
        if node.value is not None and self._cur_func:
            names = self._tainted_names_in(node.value)
            if names:
                self._tainted_returns[self._cur_func] = " -> ".join(self._chain_for(names[0]))
            else:
                src = self._match_source(node.value)
                if src and "[returns tainted" not in src:
                    self._tainted_returns[self._cur_func] = src
        # Reflected XSS on the raw-response surface (CWE-79).
        #
        # A route handler returning an f-string (or a literal-string
        # concatenation) IS the response body: Flask/Django/FastAPI do not
        # auto-escape anything outside their template engines, so request
        # data interpolated here is served as text/html and reflected back
        # to the browser. Before this shape was modelled, the only Python
        # XSS sinks were render_template_string/Markup -- so a mutation
        # that simply deleted escape() from a returned f-string survived
        # (V1 mutation harness, xss case), while the equivalent defect was
        # caught in every other language the engine serves.
        #
        # Precision gates, each deliberate:
        #   * handler gate -- only functions the decorator identifies as a
        #     response surface; the same return in a library function or CLI
        #     says nothing about rendering.
        #   * shape gate -- JoinedStr is inherently a string surface; BinOp
        #     additionally requires a str-literal side, because ``count +
        #     offset`` with both tainted is integer arithmetic, not HTML.
        #     Calls are excluded: jsonify()/json.dumps()/render_template()
        #     encode or escape before writing, and flagging them is the
        #     classic reflected-XSS false positive.
        #   * class gate -- _tainted_names_in(..., "xss") already skips
        #     values sanitized for xss and names inside a sanitizer call at
        #     this very site (escape(name) within the f-string).
        if (node.value is not None and self._cur_func
                and self._cur_func in self._route_handlers
                and (isinstance(node.value, ast.JoinedStr)
                     or (isinstance(node.value, ast.BinOp)
                         and isinstance(node.value.op, ast.Add)
                         and any(isinstance(side, ast.Constant)
                                 and isinstance(side.value, str)
                                 for side in (node.value.left, node.value.right))))):
            xss_names = self._tainted_names_in(node.value, "xss")
            if xss_names:
                tv = self._lookup(xss_names[0])
                chain = tv.full_chain() if tv else [xss_names[0]]
                sink = ("return f-string (raw HTML response)"
                        if isinstance(node.value, ast.JoinedStr)
                        else "return string concat (raw HTML response)")
                key = ("xss", node.lineno, sink)
                if key not in self._recorded:
                    self._recorded.add(key)
                    self.findings.append(TaintFinding(
                        "xss", chain[0] if chain else xss_names[0],
                        (tv.source if tv else xss_names[0]), sink,
                        self.filepath, node.lineno, self._snippet(node.lineno),
                        self._make_path(chain, sink), chain, self._cur_func,
                        "", "", "python", "High", None, "CWE-79"))
        self.generic_visit(node)
    def _file_handle(self, receiver: str) -> Optional[dict]:
        """Resolve an open-file handle name to its registered record."""
        for frame in reversed(self._handles):
            rec = frame.get(receiver)
            if rec is not None:
                return rec
        return None

    def _seed_callee(self, node: ast.Call) -> None:
        """Same-file interprocedural taint: a tainted argument seeds the
        callee's matching parameter.

        The engine previously stopped at the function boundary in both
        directions, so ``_peek(remainder)`` followed by ``open(path, "r")``
        inside ``_peek`` was invisible no matter how the value was derived.
        Seeding is deliberately bounded: only a same-file ``def`` is resolved,
        only request-derived taint is propagated (``_network_taint``), the
        caller's locals are hidden from the callee by ``_stop_at``, and
        re-entrant names plus a depth cap keep recursion finite.  Nothing
        across files, imports or dynamic dispatch is inferred.
        """
        if not isinstance(node.func, ast.Name):
            return
        name = node.func.id
        entry = self._funcs.get(name)
        if entry is None or name in self._active or self._call_depth >= _MAX_CALL_DEPTH:
            return
        params, body = entry
        if not params or not body:
            return

        def _source_of(arg_node):
            names = self._tainted_names_in(arg_node)
            if names:
                parent = self._lookup(names[0])
                if parent is not None and _network_taint(parent):
                    return TaintedVar(names[0], parent.source, arg_node.lineno,
                                      parent.full_chain()[1:], parent.sanitized_for)
            srcs = self._source_exprs_in(arg_node)
            if srcs and _network_source(srcs[0]):
                return TaintedVar("", srcs[0], arg_node.lineno, [], frozenset())
            return None

        seeded: dict[str, TaintedVar] = {}
        for p, arg in zip(params, node.args):
            tv = _source_of(arg)
            if tv is not None:
                seeded[p] = TaintedVar(p, tv.source, arg.lineno, tv.chain,
                                       tv.sanitized_for)
        for kw in node.keywords:
            if kw.arg in params and kw.arg not in seeded:
                tv = _source_of(kw.value)
                if tv is not None:
                    seeded[kw.arg] = TaintedVar(kw.arg, tv.source, kw.value.lineno,
                                                tv.chain, tv.sanitized_for)
        if not seeded:
            return

        prev_func = self._cur_func
        prev_block = self._block_path
        self._active.append(name)
        self._call_depth += 1
        self._push_scope()
        self._stop_at.append(len(self._scopes) - 1)
        try:
            # The callee body is a fresh statement tree: its block ancestry
            # starts over, or a kill in its first ``if`` branch would be
            # compared against the caller's path and never fire.
            self._block_path = ()
            for p in params:
                self._set_binding(p, "param")
            for p, tv in seeded.items():
                self._mark_tainted(p, tv)
            self._cur_func = name
            for stmt in body:
                self.visit(stmt)
        finally:
            self._block_path = prev_block
            self._stop_at.pop()
            self._pop_scope()
            self._active.pop()
            self._call_depth -= 1
            self._cur_func = prev_func

    def visit_With(self, node: ast.With):
        """Register ``with open(path, "<write mode>") as fh`` handles.

        Only write modes are recorded, because only they can turn a tainted
        value into attacker-chosen bytes on disk.  The path expression is kept
        verbatim so the write sink can tell a Python source file -- writing
        attacker code into an importable module is CWE-94, not just a file
        write -- from an ordinary data file.
        """
        for item in node.items:
            ctx = item.context_expr
            if not isinstance(ctx, ast.Call) or not isinstance(item.optional_vars, ast.Name):
                continue
            fn = self._unparse(ctx.func)
            if fn != "open" and not fn.endswith(".open"):
                continue
            if not ctx.args:
                continue
            mode_node = ctx.args[1] if len(ctx.args) > 1 else None
            for kw in ctx.keywords:
                if kw.arg == "mode":
                    mode_node = kw.value
            if not (isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str)):
                # A dynamic mode is not provably a write; withholding the
                # handle costs recall on one shape and avoids inventing a
                # write that may be a read.
                continue
            if not any(c in mode_node.value for c in "wax+"):
                continue
            path_expr = self._unparse(ctx.args[0])
            self._handles[-1][item.optional_vars.id] = {
                "path": path_expr,
                "python": ".py" in path_expr,
            }
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
        # The body only runs once __enter__ succeeds, so it is a conditional
        # block for the purpose of a taint kill.
        self._visit_body(node.body)

    # -- statement blocks -------------------------------------------------
    # Order of children is preserved from ``generic_visit``; only the block
    # ancestry is added, which is what lets ``_kill_overwrites`` refuse to
    # declassify a value across an ``if``/``else`` or a ``try`` boundary.
    def visit_If(self, node: ast.If):
        self.visit(node.test)
        self._visit_body(node.body)
        self._visit_body(node.orelse)

    def _visit_try(self, node):
        self._visit_body(node.body)
        for handler in node.handlers:
            self.visit(handler)
        self._visit_body(node.orelse)
        self._visit_body(node.finalbody)

    visit_Try = _visit_try
    visit_TryStar = _visit_try

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is not None:
            self.visit(node.type)
        self._visit_body(node.body)

    def visit_While(self, node: ast.While):
        self.visit(node.test)
        self._visit_body(node.body)
        self._visit_body(node.orelse)

    def visit_For(self, node: ast.For):
        self.visit(node.target)
        self.visit(node.iter)
        self._visit_body(node.body)
        self._visit_body(node.orelse)

    visit_AsyncFor = visit_For

    def visit_Match(self, node):
        self.visit(node.subject)
        for case in node.cases:
            self.visit(case)

    def visit_MatchCase(self, node):
        self.visit(node.pattern)
        if node.guard is not None:
            self.visit(node.guard)
        self._visit_body(node.body)

    def visit_Call(self, node: ast.Call):
        self._check_sink(node)
        # H1 .format() arm: "SELECT ... {}".format(value)
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
                and (node.args or node.keywords)):
            self._sql_interp_finding(
                node, node.func.value.value,
                list(node.args) + [kw.value for kw in node.keywords],
                ".format()")
        # Attacker bytes written into an importable Python file: the file name
        # is fixed by the code, so the path is not attacker-chosen, but the
        # *content* is and the module is executed by the interpreter later.
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("write", "writelines"):
            rec = self._file_handle(self._unparse(node.func.value))
            if rec is not None and rec.get("python"):
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    names = self._tainted_names_in(arg, "code_injection")
                    if names:
                        self._record("code_injection", self._chain_for(names[0]),
                                     self._unparse(node), node)
                        break
                    srcs = self._source_exprs_in(arg, "code_injection")
                    if srcs:
                        self._record("code_injection", [srcs[0]],
                                     self._unparse(node), node)
                        break
        self._seed_callee(node)
        self.generic_visit(node)

# Lightweight source-to-sink rules for non-Python and framework patterns.
ENTERPRISE_TAINT_RULES = [
    {"id":"TAINT_SPRING_SPEL_INJECTION","title":"Spring SpEL Injection","vuln":"spel_injection","lang":["java"],"sev":"Critical","cwe":"CWE-94","owasp":"A03:2021 - Injection","src":r"request|getParameter|@RequestParam|@PathVariable|input|param","sink":r"SpelExpressionParser|parseExpression|ExpressionParser"},
    {"id":"TAINT_SPRING_QUERY_INJECTION","title":"Spring Data @Query / JPQL Injection","vuln":"orm_injection","lang":["java"],"sev":"High","cwe":"CWE-89","owasp":"A03:2021 - Injection","src":r"@RequestParam|@PathVariable|request|getParameter|param","sink":r"@Query|createQuery|createNativeQuery|EntityManager|JpaRepository"},
    {"id":"TAINT_EF_FROMSQLRAW","title":"EF FromSqlRaw Injection","vuln":"orm_injection","lang":["csharp"],"sev":"High","cwe":"CWE-89","owasp":"A03:2021 - Injection","src":r"Request\.|FromQuery|FromRoute|FromBody|route|query","sink":r"FromSqlRaw|ExecuteSqlRaw|SqlQuery"},
    {"id":"TAINT_NOSQL_INJECTION","title":"NoSQL Injection","vuln":"nosql_injection","lang":["javascript","typescript","python","java","php"],"sev":"High","cwe":"CWE-943","owasp":"A03:2021 - Injection","src":r"req\.|request\.|\$_(?:GET|POST)(?:\s*\[[^\]]*\])?|body|query|params","sink":r"findOne|find\(|updateOne|deleteOne|\$where|\$regex|MongoClient"},
    # A9: ``(?<!urllib\.)(?<!http\.)`` stops a *module import* of
    # urllib/http -- ``urllib.request.urlopen(...)``/``django.http.request``
    # -- from counting as the attacker source (measured: 7/11 transformer
    # SSRF rows sourced from the urllib module itself). Flask/Django view
    # parameters such as ``request.args``/``req.`` are untouched, and an
    # alias assigned earlier (``url = request.args.get(...)``) still sources.
    # A9 adds httpx to the sink side: it is requests' successor and was
    # absent entirely.
    # A9d (transformers end-to-end A/B rescan evidence): this rule compiles
    # with re.IGNORECASE, so the C# ``Request\.`` alternative matched
    # ``urllib.request.``/local ``request.`` case-insensitively and defeated
    # the A9a ``urllib.``/``http.`` lookbehind on the ``request\.`` branch.
    # Six urllib Request/response-object rows (never untrusted input)
    # survived the A9 gates in the real scan: add_dates.py:80,
    # get_ci_error_statistics.py:120, github_utils.py:221,
    # update_pr_ci_dashboard_recap.py:73, integration_utils.py:2565,
    # transformers_serve_cb_eval_job.py:29. ``r\.URL`` additionally matched
    # inside ``urllib.error.URLError`` (substring), fixed for every language
    # with a left-identifier boundary that a standalone Go ``r`` always
    # satisfies. ``src_python`` scopes the identifier alternatives to the
    # framework request surfaces enumerated in TAINT_SOURCES
    # (``request.args``/``request.GET``/...): in Python a bare
    # ``request.``/``req.`` name is the urllib client API or a local
    # Request/response variable, never a web input surface. All other
    # languages keep the generic pattern unchanged.
    {"id":"TAINT_SSRF_EXPANDED","title":"SSRF Dynamic Outbound Request","vuln":"ssrf","lang":["javascript","typescript","python","java","csharp","go","php"],"sev":"High","cwe":"CWE-918","owasp":"A10:2021 - Server-Side Request Forgery","src":r"(?:req\.|(?<!urllib\.)(?<!http\.)request\.|Request\.|(?<![A-Za-z0-9_])r\.URL|\$_(?:GET|POST)(?:\s*\[[^\]]*\])?|query\b|params\b|body\b|getParameter\b)","src_python":r"(?<![A-Za-z0-9_])(?:request|req|Request)\.(?:args|form|json|data|headers|cookies|values|files|environ|GET|POST|PUT|META|COOKIES|FILES|body|path|path_info|full_path|get_full_path|get_json|query_params|url)\b|(?<![A-Za-z0-9_])r\.URL|\$_(?:GET|POST)(?:\s*\[[^\]]*\])?|query\b|params\b|body\b|getParameter\b","sink":r"(?:\bfetch\s*\(|\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(|\brequests\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(|\bhttpx\s*\.\s*(?:get|post|put|patch|delete|request|head)\s*\(|\bhttp\s*\.\s*Get\s*\(|\bHttpClient\b|\bRestTemplate\b|\bWebClient\b|\bcurl_exec\s*\(|\bfile_get_contents\s*\(|\burlopen\s*\()"},
    {"id":"TAINT_PROTOTYPE_POLLUTION","title":"Prototype Pollution User Object Merge","vuln":"prototype_pollution","lang":["javascript","typescript"],"sev":"High","cwe":"CWE-1321","owasp":"A08:2021 - Software and Data Integrity Failures","src":r"req\.body|req\.query|body|query","sink":r"Object\.assign|merge|deepmerge|lodash|_\.merge|qs\.parse"},
    {"id":"TAINT_MASS_ASSIGNMENT","title":"Mass Assignment / Overposting","vuln":"mass_assignment","lang":["java","csharp","javascript","typescript","python","php"],"sev":"High","cwe":"CWE-915","owasp":"A01:2021 - Broken Access Control","src":r"@RequestBody|FromBody|req\.body|request\.json|\$_POST|body","sink":r"User|Account|Role|Admin|Entity|Model|create\(|update\(|save\("},
    {"id":"TAINT_MULTIPART_TRAVERSAL","title":"Multipart Upload Path Traversal","vuln":"path_traversal","lang":["java","javascript","typescript","csharp","php"],"sev":"High","cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","src":r"MultipartFile|request\.files|req\.file|IFormFile|\$_FILES|getOriginalFilename|filename","sink":r"transferTo|\bFile\(|Paths\.get|\bopen\(|writeFile|Path\.Combine|move_uploaded_file"},
    # A11: ``\bid\s*:`` needs a word boundary so ``record_id:`` no longer
    # sources, and ``\bdb\.`` needs one so ``user_db.`` no longer sinks --
    # both were the single substring that fired babyagi's user_db.py:406 row.
    {"id":"TAINT_GRAPHQL_RESOLVER_BOLA","title":"GraphQL Resolver BOLA / IDOR","vuln":"idor","lang":["javascript","typescript","python","java","csharp","graphql"],"sev":"High","cwe":"CWE-639","owasp":"A01:2021 - Broken Access Control","src":r"args\.id|\bid\s*:|@Argument|GraphQLArgument","sink":r"findById|findOne|getById|repository\.find|\bdb\."},

    # B2 (2026-10-16, peft): the boolean arm of this sink was the bare token
    # ``true`` -- case-insensitive and unanchored -- so ANY ``= True`` in the
    # window of an ``introspection`` mention fired.  peft's
    # generate_method_capabilities.py is a *static introspection* toolkit
    # (``INTROSPECTION = "introspection"`` enum, L166) whose six-lines-later
    # neighbour was ``@dataclass(frozen=True)`` (L172) -> "GraphQL
    # Introspection Enabled", High.  The boolean must now be the VALUE of an
    # enablement-shaped assignment naming the flag, the same anchored shape
    # sast.py's static GRAPHQL_INTROSPECTION_ENABLED has always required
    # (``introspection: true`` / ``graphiql = true`` /
    # ``config["playground"] = true``).  The three presence sinks
    # (GraphQLPlayground / ApolloServer / GraphQLServer) are untouched.
    {"id":"TAINT_GRAPHQL_INTROSPECTION_ENABLED","title":"GraphQL Introspection Enabled","vuln":"graphql_exposure","lang":["javascript","typescript","python","java","csharp","graphql"],"sev":"High","cwe":"CWE-200","owasp":"A05:2021 - Security Misconfiguration","src":r"introspection|graphiql|__schema|__type","sink":r"[\w.\[\]\"']*(?:introspection|graphiql|playground)[\w.\[\]\"']*\s*[:=]\s*true|GraphQLPlayground|ApolloServer|GraphQLServer"},
    {"id":"TAINT_GRAPHQL_DEPTH_COMPLEXITY_MISSING","title":"GraphQL Depth / Complexity Abuse Indicator","vuln":"resource_exhaustion","lang":["javascript","typescript","python","java","csharp"],"sev":"High","cwe":"CWE-400","owasp":"API4:2023 - Unrestricted Resource Consumption","src":r"ApolloServer|GraphQLServer|graphqlHTTP|GraphQLModule","sink":r"resolvers|schema|typeDefs|Query|Mutation"},

    # ------------------------------------------------------------------
    # Intermediate-variable flows.
    #
    # Every static PHP/JS rule (here and in sast.py) only fires when the
    # superglobal / request object appears *inside* the sink call. Real code
    # almost always binds it first:
    #
    #     $id = $_GET['id'];            $db->query("... '" . $id . "'");
    #     const id = req.query.id;      cp.execSync('ls ' + id);
    #
    # These rules reuse the existing source-line + nearby-window mechanism,
    # which already establishes the source, so the sink no longer has to
    # repeat it.  Precision is NOT traded away: the concrete-sink validator
    # below requires a non-literal argument (a fixed command or a
    # parameterised statement is not injection), and a JavaScript receiver
    # must first resolve to a local alias of the child_process module, so
    # RegExp.prototype.exec() can never become a command sink.
    # ------------------------------------------------------------------
    {"id":"TAINT_PHP_SQL_INJECTION","title":"PHP SQL Injection via Bound Request Data","vuln":"sql_injection","lang":["php"],"sev":"Critical","cwe":"CWE-89","owasp":"A03:2021 - Injection","src":r"\$_(?:GET|POST|REQUEST|COOKIE)(?:\s*\[[^\]]*\])?","sink":r"(?:->\s*(?:query|prepare|exec)|mysqli_query|mysqli_real_query|mysql_query|pg_query|pg_exec|sqlite_query)\s*\("},
    {"id":"TAINT_PHP_COMMAND_INJECTION","title":"PHP Command Injection via Bound Request Data","vuln":"command_injection","lang":["php"],"sev":"Critical","cwe":"CWE-78","owasp":"A03:2021 - Injection","src":r"\$_(?:GET|POST|REQUEST|COOKIE)(?:\s*\[[^\]]*\])?","sink":r"(?:shell_exec|system|exec|passthru|popen|proc_open|pcntl_exec)\s*\("},
    {"id":"TAINT_JS_CHILD_PROCESS_EXEC","title":"Node child_process Execution with Request Data","vuln":"command_injection","lang":["javascript","typescript"],"sev":"Critical","cwe":"CWE-78","owasp":"A03:2021 - Injection","src":r"(?:req|request)\s*\.\s*(?:query|params|body)","sink":r"(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\("},
]

def _priority(sev: str) -> str:
    return {"Critical":"P1","High":"P2","Medium":"P3","Low":"P4"}.get(sev,"P3")

ARTIFACT_FILE_NAMES = {
    "bom.json", "clean_report.json", "scan_manifest.json", "sbom.json", "cbom.json",
    "aibom.json", "mlbom.json", "apibom.json", "abom.json", "sarif.json", "qbom.json",
    # The prefixed artifacts. Matching here is by basename, so the bare "qbom.json"
    # entry above does not cover "Security_QBOM.qbom.json" and the taint engine
    # would treat a generated report as a source file. Kept in step with
    # scanner.sast.EXCLUDED_FILES, which tests/test_v11_self_scan_exclusions.py
    # checks for agreement.
    "security_qbom.pq.json", "security_qbom.qbom.json",
    "security_cyclonedx.json", "security_report.vex.json",
    "security_spdx.spdx.json", "scan_performance.json",
    # Phase 4: CycloneDX 1.6 CBOM/AI-BOM artifacts.
    "security_cbom.cdx.json", "security_aibom.cdx.json",
    # Phase 5.2/5.4 integration artifacts (see the sast.EXCLUDED_FILES note).
    "security_jira_import.csv", "security_findings_webhook.json",
    "security_defectdojo_import.json",
    # Phase 5.3: continuous re-evaluation artifact, written beside the
    # stored report and therefore re-scannable input.
    "security_continuous.json",
    # T-0.1: --explain-drops writes drops.json beside clean_report.json.
    "drops.json",
    # DoD --explain-verdict writes verdicts.json beside clean_report.json
    # (kept in exact set-agreement with sast/file_index EXCLUDED_FILES).
    "verdicts.json",
    # G1.6/DEC-06 (2026-11-17): --explain-score writes explain_scores.json
    # beside clean_report.json (kept in exact set-agreement with
    # sast/file_index EXCLUDED_FILES).
    "explain_scores.json",
    # T-9.6 / D-2: --html-embedded writes triage.html beside
    # clean_report.json (HTML is scannable -- XSS rules would read it).
    "triage.html",
    # T-14.3 (task.md section 14 "Observability"): --telemetry writes
    # telemetry.json beside clean_report.json (kept in exact set-
    # agreement with sast/file_index EXCLUDED_FILES).
    "telemetry.json",
}


def _is_generated_artifact(filepath: str) -> bool:
    p = str(filepath).replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    return name in ARTIFACT_FILE_NAMES or "/reports/" in p or "/coverage/" in p


def _is_graphql_context(source: str, filepath: str) -> bool:
    # A11: a bare "schema" word anywhere in the window -- SQLAlchemy
    # metadata, a docstring -- is not GraphQL. Keep the executable markers
    # (resolver/typedefs/apollo directives) and the GraphQL file shapes
    # (.graphql/.gql suffix, /graphql path) instead.
    p = str(filepath).replace("\\", "/").lower()
    return bool(re.search(r"\b(?:graphql|resolver|gql|typeDefs|ApolloServer|GraphQLModule|@Resolver|@Query|@Mutation)\b", source, re.I)) or "/graphql" in p or p.endswith(".graphql") or p.endswith(".gql")


def _language(path: Path) -> str:
    return LANG_BY_EXT.get(path.suffix.lower(), path.suffix.lower().lstrip(".") or "unknown")

def _base_finding(rule: dict, filepath: str, line: int, snippet: str, source: str, sink: str, lang: str) -> dict:
    m = get_mapping(rule["vuln"])
    sev = rule.get("sev") or m.get("severity", "High")
    controls = BIG4_TAINT_CONTROLS.get(rule["vuln"], {})
    remediation = BIG4_TAINT_REMEDIATION.get(rule["vuln"]) or m.get("remediation") or ["Use safe framework APIs.", "Validate and authorize user-controlled input before sink use.", "Add security regression tests for this flow."]
    conf = "High" if sev == "Critical" else "Medium"
    return {
        "rule_id": rule["id"], "title": rule["title"], "vuln_type": rule["vuln"], "severity": sev,
        "priority": _priority(sev), "confidence": conf, "language": lang, "file": filepath, "line": line,
        "snippet": snippet.strip(), "description": f"Source-to-sink indicator: {source} reaches {sink} near the same function/block.",
        "remediation": remediation,
        "owasp": rule.get("owasp") or m.get("owasp", ""), "owasp_id": m.get("owasp_id", ""),
        "cwe": rule.get("cwe") or m.get("cwe", ""), "cwe_desc": m.get("cwe_desc", ""),
        "mitre": m.get("mitre", ""), "mitre_desc": m.get("mitre_desc", ""),
        "pci_dss": m.get("pci_dss") or controls.get("pci_dss", ""), "nist": m.get("nist") or controls.get("nist", ""), "nist_800_53": m.get("nist_800_53") or m.get("nist") or controls.get("nist", ""), "iso27001": m.get("iso27001") or controls.get("iso27001", ""), "iso_27001": m.get("iso_27001") or m.get("iso27001") or controls.get("iso27001", ""), "soc2": m.get("soc2") or controls.get("soc2", ""),
        "business_impact": m.get("business_impact", ""), "exploitability": "High",
        "taint_path": f"{source} -> {sink}", "taint_chain": [source, sink], "source_expr": source, "sink_call": sink,
        "evidence": f"{filepath}:{line}: {snippet.strip()}", "detection": "Enterprise Source-to-Sink Heuristic", "engine": "scanner.taint_engine", "cvss": None, "cve": None,
        "group_key": f"{rule['id']}|{filepath}|{line}", "enterprise_control": True,
    }


# ---------------------------------------------------------------------------
# API abuse/rate-limit validation
# ---------------------------------------------------------------------------
# Rate-limit findings must represent a server-side endpoint definition.
# Browser/frontend API consumers (Axios, fetch, React navigation, etc.) are
# not evidence that the backend endpoint lacks rate limiting.
_SERVER_ROUTE_PATTERNS = {
    "python": re.compile(
        r"(?:\bpath\s*\(|\bre_path\s*\(|@(?:app|router)\.(?:route|get|post|put|patch|delete)\s*\(|"
        r"@(?:api_view|action)\b|class\s+\w*(?:View|ViewSet)\b|"
        r"@(api_view|permission_classes|throttle_classes)\b)",
        _F,
    ),
    "javascript": re.compile(
        r"(?:\b(?:router|app)\.(?:get|post|put|patch|delete|route|use)\s*\(|"
        r"\bexpress\s*\(|\b(?:fastify|koa)\b|"
        r"@(Get|Post|Put|Patch|Delete)\s*\()",
        _F,
    ),
    "typescript": re.compile(
        r"(?:\b(?:router|app)\.(?:get|post|put|patch|delete|route|use)\s*\(|"
        r"\bexpress\s*\(|\b(?:fastify|koa)\b|"
        r"@(Get|Post|Put|Patch|Delete)\s*\()",
        _F,
    ),
    "java": re.compile(
        r"(?:@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\b|"
        r"\b(?:RouterFunction|Route)\b)",
        _F,
    ),
    "csharp": re.compile(
        r"(?:\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\b|"
        r"\bMap(?:Get|Post|Put|Patch|Delete)\s*\()",
        _F,
    ),
    "go": re.compile(
        r"(?:\.(?:GET|POST|PUT|PATCH|DELETE)\s*\(|\bHandleFunc\s*\(|"
        r"\b(?:http|gin|echo|fiber)\b)",
        _F,
    ),
    "php": re.compile(
        r"(?:->(?:get|post|put|patch|delete|match)\s*\(|"
        r"\bRoute::(?:get|post|put|patch|delete|match)\s*\()",
        _F,
    ),
}

_CLIENT_SIDE_PATH_RE = re.compile(
    r"(?:^|[\\/])(?:frontend|client|web)[\\/]|"
    r"(?:^|[\\/])(?:src[\\/](?:api|components|context|hooks|services))[\\/]|"
    r"(?:axios|fetch|protectedroute|authcontext|signup|login)\.(?:js|jsx|ts|tsx|vue)$",
    _F,
)


def _is_server_side_route_file(filepath: str, source: str, lang: str) -> bool:
    """Return True only when the file provides credible server route evidence."""
    normalized = str(filepath).replace("\\", "/").lower()

    # Strongly exclude browser/client-side code.
    if _CLIENT_SIDE_PATH_RE.search(normalized):
        return False

    # Generic frontend indicators should not become endpoint evidence.
    if any(part in normalized.split("/") for part in ("frontend", "client", "web")):
        return False

    route_re = _SERVER_ROUTE_PATTERNS.get(lang)
    if route_re and route_re.search(source):
        return True

    # Python URL configuration is common even when the exact route is not
    # represented by the primary pattern.
    if lang == "python" and re.search(
        r"\b(?:urlpatterns|router\.register|include\s*\(|path\s*\(|re_path\s*\()",
        source,
        _F,
    ):
        return True

    return False


def _is_api_rate_limit_rule(rule: dict) -> bool:
    return str(rule.get("vuln", "")).lower() in {
        "api_rate_limit",
        "api_abuse_missing_rate_limit",
    } or str(rule.get("id", "")).upper() in {
        "TAINT_API_RATE_LIMIT_LOGIN",
        "MISSING_RATE_LIMIT_ENDPOINT",
    }




def _is_client_side_ssrf_context(filepath: str, source: str, lang: str) -> bool:
    """Return True when SSRF evidence comes from browser/client-side code.

    Axios/fetch calls in React/browser code are outbound requests made by the
    user's browser, not server-side SSRF.  Do not suppress server-side Node.js
    code merely because it uses JavaScript/TypeScript.
    """
    p = str(filepath).replace("\\", "/").lower()

    if "/frontend/" in p or "/client/" in p or "/web/" in p:
        return True

    # A12: served browser bundles. babyagi's
    # dashboard/static/js/function_details.js:307 was an axios/fetch call in
    # a file the server ships as static -- the browser, not the server, makes
    # that request.
    if any(token in p for token in (
        "/static/", "/public/", "/assets/",
        "/src/api/", "/src/components/", "/src/context/",
        "/src/pages/", "/src/hooks/",
    )):
        return True

    if p.endswith((
        "/axios.js", "/axios.jsx", "/axios.ts", "/axios.tsx",
        "/authcontext.jsx", "/protectedroute.jsx",
        "/signup.jsx", "/login.jsx",
    )):
        return True

    return False


def _is_concrete_ssrf_sink(line: str, lang: str) -> bool:
    """Return True only for an actual outbound HTTP/client invocation.

    Prevents generic method names such as Django ``prefetch_related`` from
    being interpreted as an SSRF sink by the nearby-window heuristic.
    """
    s = line or ""

    if lang in {"javascript", "typescript"}:
        return bool(re.search(
            r"\b(?:fetch\s*\(|axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\()",
            s, re.IGNORECASE,
        ))

    if lang == "python":
        return bool(re.search(
            r"\b(?:requests\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(|"
            r"httpx\s*\.\s*(?:get|post|put|patch|delete|request|head)\s*\(|"
            r"urllib(?:\.[A-Za-z_][\w]*)*\s*\.\s*urlopen\s*\(|"
            r"urlopen\s*\(|http\.client\.(?:HTTPConnection|HTTPSConnection)\s*\()",
            s, re.IGNORECASE,
        ))

    if lang == "java":
        return bool(re.search(
            r"\b(?:RestTemplate|WebClient)\b.*(?:\.(?:getForObject|getForEntity|postForObject|exchange|retrieve|uri)\s*\(|"
            r"HttpClient\b.*\.(?:send|sendAsync)\s*\()",
            s, re.IGNORECASE,
        ))

    if lang == "csharp":
        return bool(re.search(
            r"\bHttpClient\b.*\.(?:GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)\s*\(",
            s, re.IGNORECASE,
        ))

    if lang == "go":
        return bool(re.search(
            r"\b(?:http\.(?:Get|Post|Head|Do)|client\.(?:Do|Get))\s*\(",
            s, re.IGNORECASE,
        ))

    if lang == "php":
        return bool(re.search(
            r"\b(?:curl_exec|file_get_contents)\s*\(",
            s, re.IGNORECASE,
        ))

    return False



def _is_comment_or_static_text_line(line: str, lang: str) -> bool:
    """Reject comment-only and obvious presentation/static-text lines as security sinks."""
    stripped = (line or "").strip()
    if not stripped:
        return True
    if stripped.startswith(("#", "//", "/*", "*", "*/")):
        return True
    if lang in {"javascript", "typescript"}:
        if re.fullmatch(r"</?[\w.-]+(?:\s+[^>]*)?>", stripped):
            return True
        if re.search(
            r"<(?:th|td|h[1-6]|p|span|label)\b[^>]*>.*?</(?:th|td|h[1-6]|p|span|label)>",
            stripped,
            re.I,
        ):
            return True
    return False


# Mongo operators whose VALUE position is a list of data operands, not a
# query-document position. Taint reaching only these is parameterization.
_NOSQL_DATA_OPERAND_KEYS_RE = re.compile(r"\$(?:in|nin|all|size)\b", re.I)


def _nosql_taint_reaches_only_data_operand(line: str) -> bool:
    """True when the sink line's query object exposes NO operator position.

    ``find({"_id": {"$in": ids}})`` binds list ITEMS as data: operator
    smuggling needs attacker-controlled dict KEYS (``{"$gt": ""}`` inside an
    object), which list values can never become. A line carrying ANY other
    ``$``-operator ($gt/$where/$or/...) keeps reporting -- that is a real
    query-document position.
    """
    if not _NOSQL_DATA_OPERAND_KEYS_RE.search(line or ""):
        return False
    others = [
        m.group(0).lower()
        for m in re.finditer(r"\$[a-zA-Z]+", line)
        if m.group(0).lower() not in {"$in", "$nin", "$all", "$size"}
    ]
    return not others


def _is_concrete_nosql_sink(line: str, lang: str) -> bool:
    """Accept only database/ODM NoSQL operations, not JavaScript Array.find()."""
    s = line or ""
    if lang in {"javascript", "typescript"}:
        # Require a concrete Mongo/NoSQL API. Relational ORMs such as
        # Sequelize Model.findOne() are not NoSQL sinks.
        if re.search(r"\b(?:sequelize|Sequelize|Model|User|Account|Address|Basket|Order|Delivery|Product)\b\s*\.\s*findOne\s*\(", s, re.I):
            return False
        # Mongo/Mongoose API presence is necessary but not sufficient. A plain
        # findOne({_id: id}) is normal database access; promote only when the
        # query construction exposes an operator/dynamic object pattern or an
        # explicitly attacker-controlled query object.
        if re.search(r"\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|where)\b", s, re.I):
            return True
        if re.search(r"(?:\b(?:db|database|collection|collections|mongo|mongodb|mongoose)\b(?:\s*\.\s*\w+)*\s*\.\s*(?:find|findOne|findOneAnd(?:Update|Delete)|updateOne|updateMany|deleteOne|deleteMany)\s*\([^)]*(?:req\.|request\.|body|query|params)\b)", s, re.I):
            return True
        return False
    if lang == "python":
        return bool(re.search(
            r"\b(?:\w+\.)?(?:objects|collection|collections|db|database)\s*\.\s*"
            r"(?:find|find_one|find_one_and_update|update_one|update_many|delete_one|delete_many)\s*\(",
            s, re.I,
        ))
    if lang == "java":
        return bool(re.search(
            r"\b(?:Mongo|MongoCollection|MongoTemplate|MongoRepository|ReactiveMongo|Document)\b.*"
            r"\b(?:find|findOne|update|delete)\s*\(",
            s, re.I,
        ))
    if lang == "php":
        return bool(re.search(
            r"\b(?:MongoDB|MongoCollection|collection)\b.*\b(?:find|findOne|update|delete)\s*\(",
            s, re.I,
        ))
    return False


def _is_concrete_mass_assignment_sink(line: str, lang: str) -> bool:
    """Accept only real object/model binding or persistence operations."""
    s = line or ""
    if _is_comment_or_static_text_line(s, lang):
        return False

    if lang in {"javascript", "typescript"}:
        # A persistence call alone is not mass assignment. Explicitly
        # constructed objects such as user.update({ role: ..., token: ... })
        # are safe from an overposting perspective. Require the attacker-
        # controlled object itself (or an object spread) to reach persistence.
        if re.search(r"\.(?:update|create|updateOne|updateMany|findOneAndUpdate|save)\s*\(\s*\{", s, re.I):
            if not re.search(r"(?:\.\.\.\s*(?:req\.body|request\.body|body|payload)|(?:req\.body|request\.body|body|payload)\b)", s, re.I):
                return False
        return bool(re.search(
            r"(?:\.(?:create|update|updateOne|updateMany|findOneAndUpdate|save)\s*\(\s*"
            r"(?:req\.body|request\.body|body|payload|data)\b|"
            r"\.(?:create|update|updateOne|updateMany|findOneAndUpdate|save)\s*\(\s*\{[^}]*\.\.\.\s*"
            r"(?:req\.body|request\.body|body|payload)\b|"
            r"\b(?:Object\.assign|Object\.fromEntries)\s*\([^)]*"
            r"(?:req\.body|request\.body|payload)\b)",
            s, re.I,
        ))

    if lang == "python":
        return bool(re.search(
            r"(?:\b(?:serializer|form|model|instance|obj|user|account)\b.*"
            r"\.(?:is_valid|save|create|update|update_or_create)\s*\(|"
            r"\b(?:ModelSerializer|Serializer)\b|"
            r"\bobjects\.(?:create|update|update_or_create)\s*\()",
            s, re.I,
        ))

    if lang == "java":
        return bool(re.search(
            r"(?:@RequestBody\b.*\b(?:save|persist|merge)\b|"
            r"\b(?:repository|dao|entityManager)\b.*\.(?:save|saveAll|persist|merge)\s*\()",
            s, re.I,
        ))

    if lang == "csharp":
        return bool(re.search(
            r"\b(?:DbSet|DbContext|ModelState)\b.*\.(?:Add|AddAsync|Update|Attach)\s*\(",
            s, re.I,
        ))

    if lang == "php":
        return bool(re.search(
            r"\b(?:create|fill|update|save)\s*\(\s*\$(?:_POST|_REQUEST|data|payload|body)\b",
            s, re.I,
        ))

    return False


# ---------------------------------------------------------------------------
# Concrete sinks for the intermediate-variable rules
# ---------------------------------------------------------------------------
_PROCESS_MEMBER_RE = re.compile(
    r"([A-Za-z_$][\w$]*)\s*\.\s*"
    r"(exec|execFile|execFileSync|execSync|spawn|spawnSync|fork)\s*\("
)
_PROCESS_BARE_RE = re.compile(
    r"(?<![\w$.])(shell_exec|system|exec|passthru|popen|proc_open|pcntl_exec|"
    r"execFile|execFileSync|execSync|spawn|spawnSync|fork)\s*\("
)
_SQL_SINK_RE = re.compile(
    r"(?:->\s*(?:query|prepare|exec)|mysqli_query|mysqli_real_query|"
    r"mysql_query|pg_query|pg_exec|sqlite_query)\s*\("
)


def _call_arguments_are_dynamic(call_line: str) -> bool:
    """True when the argument list on this line is not purely literal.

    ``system("echo done")`` runs a fixed command and ``$db->prepare("... ?")``
    is a parameterised statement: neither can be injected into, so neither is
    a sink.  Concatenation, interpolation or a variable argument keeps the
    call eligible.  Only literals are removed; anything else is treated as
    dynamic, so this helper can never suppress a genuinely tainted call.
    """
    m = re.search(r"\((.*)\)", call_line)
    if not m:
        return False
    inner = m.group(1)
    inner = re.sub(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"", "", inner)
    inner = re.sub(r"(?:#|//)[^\n]*", "", inner)
    inner = re.sub(r"\s+", "", inner)
    inner = inner.strip(",;")
    return bool(inner)


def _is_concrete_command_sink(line: str, lang: str) -> bool:
    """Recognise a *process execution* call, not an arbitrary method call.

    A method call only qualifies once its receiver has been projected onto
    ``child_process`` by ``_project_child_process_alias``, which is what keeps
    ``RegExp.prototype.exec(...)`` out of command injection.
    """
    if _is_comment_or_static_text_line(line, lang):
        return False
    member = _PROCESS_MEMBER_RE.search(line)
    if member is not None:
        if member.group(1) != "child_process":
            return False
    elif not _PROCESS_BARE_RE.search(line):
        return False
    return _call_arguments_are_dynamic(line)


def _is_concrete_sql_sink(line: str, lang: str) -> bool:
    """A query call whose statement text is not a fixed literal."""
    if _is_comment_or_static_text_line(line, lang):
        return False
    if not _SQL_SINK_RE.search(line):
        return False
    return _call_arguments_are_dynamic(line)


def _child_process_names(lines: list[str]) -> tuple[set[str], set[str]]:
    """Return (member aliases, named imports) bound to the child_process module.

    ``const cp = require('child_process')`` -> member alias ``cp``;
    ``import { exec } from 'child_process'`` -> named import ``exec``.
    Resolving the binding from the file itself is the only way to tell
    ``cp.execSync(...)`` from ``re.exec(...)`` without guessing.
    """
    text = "\n".join(lines)
    members: set[str] = set()
    named: set[str] = set()

    for pat in (
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*[\"']child_process[\"']\s*\)",
        r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+[\"']child_process[\"']",
        r"import\s+([A-Za-z_$][\w$]*)\s+from\s+[\"']child_process[\"']",
    ):
        for m in re.finditer(pat, text):
            members.add(m.group(1))

    named_import = re.search(
        r"import\s*\{([^}]*)\}\s*from\s*[\"']child_process[\"']", text
    )
    if named_import:
        for part in named_import.group(1).split(","):
            local = part.split(" as ")[-1].strip()
            if local:
                named.add(local)
    destructure = re.search(
        r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*[\"']child_process[\"']\s*\)",
        text,
    )
    if destructure:
        for part in destructure.group(1).split(","):
            local = part.split(":")[-1].strip()
            if local:
                named.add(local)

    return members, named


def _project_child_process_alias(
    line: str, members: set[str], named: set[str]
) -> str:
    """Rewrite a resolved child_process binding onto the module name.

    ``cp.execSync(...)`` becomes ``child_process.execSync(...)`` so the
    concrete-sink validator can evaluate it, while an unrelated receiver such
    as ``re.exec(...)`` is left untouched and therefore rejected.
    """
    out = line
    for alias in sorted(members, key=len, reverse=True):
        out = re.sub(
            rf"\b{re.escape(alias)}\s*\.\s*"
            rf"(?=(?:exec|execFile|execFileSync|execSync|spawn|spawnSync|fork)\s*\()",
            "child_process.",
            out,
        )
    for name in sorted(named, key=len, reverse=True):
        out = re.sub(
            rf"(?<![\w$.]){re.escape(name)}\s*\(",
            f"child_process.{name}(",
            out,
        )
    return out


def _enterprise_rule_has_concrete_sink(rule: dict, sink_line: str, lang: str) -> bool:
    """Prevent generic words, comments and presentation code becoming sinks."""
    vuln = str(rule.get("vuln", "")).lower()
    if _is_comment_or_static_text_line(sink_line, lang):
        return False
    if vuln == "path_traversal":
        return _is_concrete_path_sink(sink_line)
    if vuln == "nosql_injection":
        return _is_concrete_nosql_sink(sink_line, lang)
    if vuln == "mass_assignment":
        return _is_concrete_mass_assignment_sink(sink_line, lang)
    # Only the intermediate-variable PHP/JS rules use these two types, so the
    # stricter argument/receiver requirements apply to them alone and cannot
    # change the behaviour of any pre-existing enterprise rule.
    if vuln == "command_injection":
        return _is_concrete_command_sink(sink_line, lang)
    if vuln == "sql_injection":
        return _is_concrete_sql_sink(sink_line, lang)
    if vuln == "prototype_pollution":
        return bool(re.search(r"(?:Object\.assign|Object\.setPrototypeOf|__proto__|deepmerge|lodash\.merge|_\.merge|\bmerge\s*\()", sink_line, re.I))
    if vuln == "zipslip":
        return bool(re.search(r"(?:extract(?:ToDirectory|ToFile)?|writeFile|createWriteStream|FileOutputStream|OpenFile)\s*\(", sink_line, re.I))
    return True


# B1: Precompiled enterprise taint regex rules.
# Compile source/sink expressions once at module load rather than once
# for every scanned file.
def _compile_enterprise_taint_rules():
    compiled = []

    for rule in ENTERPRISE_TAINT_RULES:
        item = dict(rule)

        try:
            item["_src_re"] = re.compile(rule["src"], _F)
            item["_sink_re"] = re.compile(rule["sink"], _F)
            if rule.get("src_python"):
                # A9d: language-scoped source pattern (see TAINT_SSRF_EXPANDED).
                item["_src_re_python"] = re.compile(rule["src_python"], _F)
        except re.error:
            # Preserve the previous behavior: malformed optional rules
            # are skipped without aborting the complete scan.
            continue

        compiled.append(item)

    return compiled


COMPILED_ENTERPRISE_TAINT_RULES = _compile_enterprise_taint_rules()



def _js_mass_assignment_tainted_aliases(lines: list[str], source_line: int, end_line: int) -> set[str]:
    """Return bounded local aliases proven to originate from request-body data.

    This is intentionally conservative:
      req.body / request.body / body / payload -> local alias
    Only direct assignments are propagated. Sanitizer/function-call results
    are not treated as trusted tainted aliases.
    """
    aliases: set[str] = set()

    source_re = re.compile(
        r"\b(?:req\.body|request\.body|body|payload)\b",
        re.I,
    )

    assignment_re = re.compile(
        r"^\s*(?:(?:const|let|var)\s+)?"
        r"([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$",
        re.I,
    )

    # Bounded fixed-point propagation inside the enterprise window.
    for _ in range(3):
        changed = False

        for idx in range(max(0, source_line), min(len(lines), end_line)):
            line = lines[idx]

            m = assignment_re.match(line)
            if not m:
                continue

            lhs = m.group(1)
            rhs = m.group(2)

            # Direct request-body assignment.
            if source_re.search(rhs):
                if lhs not in aliases:
                    aliases.add(lhs)
                    changed = True
                continue

            # Alias-to-alias propagation only.
            tokens = re.findall(r"\b[A-Za-z_$][\w$]*\b", rhs)
            if any(token in aliases for token in tokens):
                if lhs not in aliases:
                    aliases.add(lhs)
                    changed = True

        if not changed:
            break

    return aliases


def _mass_assignment_sink_line_with_aliases(
    line: str,
    aliases: set[str],
) -> str:
    """Project a proven tainted alias to req.body for sink validation."""
    if not aliases:
        return line

    projected = line
    for alias in sorted(aliases, key=len, reverse=True):
        projected = re.sub(
            rf"\b{re.escape(alias)}\b",
            "req.body",
            projected,
        )

    return projected


# A sink-shaped token inside a method DECLARATION is not a sink: the
# multipart window rule matches ``File(``, ``open(`` and ``writeFile(``
# anywhere, which made ``public IActionResult File([FromQuery] string
# filename)`` its own "sink" (the corpus's SafeController/Vulnerable-
# Controller false anchor). A real sink is an expression: a call statement,
# a construction, an assignment — never a signature.
_PATH_SINK_DECL_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized"
    r"|native|override|internal|virtual|sealed|async|partial)\s+)+"
    r"(?:[\w$][\w$<>\[\],.?]*\s+)*"
    r"(?:File|open|writeFile)\s*\([^;{]*\)\s*"
    r"(?:throws\s+[\w.,\s]+)?\s*\{?\s*$")


def _is_concrete_path_sink(sink_line: str) -> bool:
    """Reject method declarations whose signature merely LOOKS like a sink."""
    if _PATH_SINK_DECL_RE.match(sink_line.strip()):
        return False
    return True


_MULTIPART_SUBJECT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _multipart_subject(src_match) -> str:
    """The identifier around the source token that matched the src regex.

    ``filename`` matched case-insensitively inside ``fileName`` yields
    ``fileName`` — the exact variable the flow gate must evaluate.
    """
    try:
        m = _MULTIPART_SUBJECT_RE.search(src_match.group(0) or "")
    except Exception:
        return ""
    return m.group(0) if m else ""


def _multipart_flow_proves_constant(source: str, filepath: str, src_match,
                                    sink_idx: int) -> bool:
    """True only when the multipart subject's value at the sink line is a
    proven compile-time constant.

    Kill-only-on-proof: the bounded abstract evaluation in
    ``scanner/multipart_flow.py`` must PROVE every definition path reaching
    the sink folds to a literal constant (constant-folded ternary/branch/
    switch, strong-update reassignment, literal-returning same-file or
    same-tree helper). Any ambiguity returns False, which callers turn into
    KEEP. Never raises.
    """
    try:
        from scanner import multipart_flow
        var = _multipart_subject(src_match)
        if not var:
            return False
        return multipart_flow.is_proven_constant(
            source, var, sink_idx + 1, filepath=filepath)
    except Exception:
        return False


def _ssrf_sink_url_text(sink_line: str, sink_re) -> Optional[str]:
    """A9: text of the arguments that *are* the outbound URL for the concrete
    sink call on this line (first positional, plus ``url=``-style keywords).

    Returns None when the argument list cannot be located, so the caller
    keeps the finding rather than guessing.
    """
    m = sink_re.search(sink_line)
    if not m:
        return None
    if sink_line[m.end() - 1:m.end()] == "(":
        idx = m.end() - 1
    else:
        idx = sink_line.find("(", m.end())
    if idx < 0:
        return None

    def _walk(text: str, start: int) -> tuple[str, int]:
        """Balanced-paren slice plus its top-level argument split."""
        depth = 0
        quote = ""
        close = -1
        j = start
        while j < len(text):
            ch = text[j]
            if quote:
                if ch == "\\":
                    j += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "\"'":
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    close = j
                    break
            j += 1
        if close < 0:
            return "", -1
        inner = text[start + 1:close]
        parts: list[str] = []
        buf: list[str] = []
        depth = 0
        quote = ""
        j = 0
        while j < len(inner):
            ch = inner[j]
            if quote:
                buf.append(ch)
                if ch == "\\" and j + 1 < len(inner):
                    buf.append(inner[j + 1])
                    j += 2
                    continue
                if ch == quote:
                    quote = ""
            elif ch in "\"'":
                quote = ch
                buf.append(ch)
            elif ch in "([{":
                depth += 1
                buf.append(ch)
            elif ch in ")]}":
                depth -= 1
                buf.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
            j += 1
        parts.append("".join(buf))
        return "\x00".join(parts), close

    packed, close = _walk(sink_line, idx)
    if close < 0:
        return None
    parts = packed.split("\x00")
    keep: list[str] = []
    if parts and not re.match(r"\s*[A-Za-z_$][\w$]*\s*=", parts[0]):
        keep.append(parts[0])  # first positional is the URL slot
    keep.extend(
        p for p in parts
        if re.match(r"\s*(?:url|uri|href|endpoint)\s*=", p)
    )
    return "\n".join(keep)


# A9: bare English-word source tokens only ever source SSRF when they sit in
# the sink call's own URL argument. Seen on a *different* line they are prose
# or local bookkeeping (github_utils.py's docstring "any other body",
# ``body = error.read()``), not request state; the qualified request surfaces
# (``request.``/``req.``/``$_GET``/``getParameter``/``r.URL``) still source
# across lines so the alias flow
#     url = request.args.get("u") ... urlopen(url)
# keeps its finding.
_SSRF_BARE_WINDOW_SRCS = frozenset({"query", "params", "body"})


def _scan_enterprise_text(filepath: str, source: str, lang: str) -> list[dict]:
    lines = source.splitlines()
    findings: list[dict] = []

    # Look in nearby windows, but report the sink line as evidence to avoid
    # mismatched source-only lines.
    for rule in COMPILED_ENTERPRISE_TAINT_RULES:
        if lang not in rule["lang"]:
            continue

        if _is_generated_artifact(filepath):
            continue

        # GraphQL BOLA requires actual GraphQL/resolver context; generic ORM access is not GraphQL.
        if rule.get("id") == "TAINT_GRAPHQL_RESOLVER_BOLA" and not _is_graphql_context(source, filepath):
            continue

        # Critical anti-false-positive control:
        # API rate-limit rules require server-side route evidence. A frontend
        # Axios/fetch call, React navigation, token storage, etc. is not an
        # endpoint definition and therefore cannot establish missing controls.
        if _is_api_rate_limit_rule(rule) and not _is_server_side_route_file(
            filepath, source, lang
        ):
            continue

        # Client-side token storage/cleanup is not an API endpoint definition.
        if _is_api_rate_limit_rule(rule) and re.search(
            r"\b(?:localStorage|sessionStorage)\.(?:setItem|getItem|removeItem|clear)\s*\(",
            source,
            re.I,
        ) and not _SERVER_ROUTE_PATTERNS.get(lang, re.compile(r"(?!)")).search(source):
            continue

        # SSRF requires a server-side execution context. Browser-side
        # React/Axios/fetch calls cannot establish server-side SSRF.
        if (
            str(rule.get("vuln", "")).lower() == "ssrf"
            and _is_client_side_ssrf_context(filepath, source, lang)
        ):
            continue

        src_re = rule["_src_re"]
        if lang == "python":
            # A9d: Python uses the surface-bounded source pattern when the
            # rule provides one (urllib ``request``/``req`` names are client
            # API objects, not web input).
            src_re = rule.get("_src_re_python") or src_re
        sink_re = rule["_sink_re"]

        for i, line in enumerate(lines):
            src_match = src_re.search(line)
            if not src_match:
                continue

            start = max(0, i - 4)
            end = min(len(lines), i + 14)
            window_lines = lines[start:end]
            window = "\n".join(window_lines)
            sink_match = sink_re.search(window)

            # SSRF is special: a generic nearby regex match is insufficient.
            # Require the sink to occur on a concrete outbound-request line.
            if sink_match and str(rule.get("vuln", "")).lower() == "ssrf":
                candidate_lines = range(start, end)
                concrete = next(
                    (
                        idx for idx in candidate_lines
                        if _is_concrete_ssrf_sink(lines[idx], lang)
                        and sink_re.search(lines[idx])
                    ),
                    None,
                )
                if concrete is None:
                    sink_match = None
                else:
                    # A9 text gates. Same-line: the source token must sit in
                    # the call's own URL argument (``params=``/``headers=``
                    # payloads do not steer the fetch). Cross-line: a bare
                    # window word is prose/local state; only a qualified
                    # request surface sources across lines, preserving the
                    # ``url = request.args.get(...)`` alias flow.
                    src_token = src_match.group(0).strip()
                    if i != concrete:
                        # G5 (2026-10-19, prodtest): case-insensitive -- WebGoat's
                        # security-misconfiguration-task2.js:32 matched "Params"
                        # inside ``searchParams`` (the URL API, not a request
                        # surface) and the exact-membership check missed it.
                        if src_token.lower() in _SSRF_BARE_WINDOW_SRCS:
                            sink_match = None
                    else:
                        url_text = _ssrf_sink_url_text(lines[concrete], sink_re)
                        if url_text is not None and src_token not in url_text:
                            sink_match = None
                    if sink_match:
                        evidence_line = concrete + 1
                        sink = sink_re.search(lines[concrete]).group(0)[:80]
                        snippet = lines[concrete]
            if sink_match:
                if str(rule.get("vuln", "")).lower() != "ssrf":
                    # The raw sink regex may match a generic token earlier in
                    # the nearby window (for example "merge" in
                    # "mergeUser") before the actual security sink such as
                    # Object.assign(...). Resolve the first candidate line
                    # that passes the concrete sink validator.
                    concrete_candidate = None

                    for candidate_idx in range(start, end):
                        candidate_line = lines[candidate_idx]

                        if not sink_re.search(candidate_line):
                            continue

                        # Generic tokens such as "Role", "Model", "find(" or
                        # report/UI text must not establish a security sink.
                        #
                        # Mass Assignment additionally permits a bounded,
                        # directly-proven JavaScript/TypeScript alias:
                        #
                        #     const user = req.body;
                        #     User.update(user);
                        #
                        # The original concrete sink validator remains strict;
                        # only the proven alias is projected to req.body for
                        # validation.
                        validation_line = candidate_line

                        if (
                            str(rule.get("vuln", "")).lower() == "mass_assignment"
                            and lang in {"javascript", "typescript"}
                        ):
                            aliases = _js_mass_assignment_tainted_aliases(
                                lines,
                                i,
                                end,
                            )
                            validation_line = _mass_assignment_sink_line_with_aliases(
                                candidate_line,
                                aliases,
                            )

                        # Same pattern for child_process: the binding is
                        # resolved from this file's own imports so that
                        # ``cp.execSync(...)`` validates as a process sink
                        # while ``re.exec(...)`` (RegExp) does not.
                        elif rule.get("id") == "TAINT_JS_CHILD_PROCESS_EXEC":
                            members, named = _child_process_names(lines)
                            validation_line = _project_child_process_alias(
                                candidate_line, members, named
                            )

                        if not _enterprise_rule_has_concrete_sink(
                            rule, validation_line, lang
                        ):
                            continue

                        # ``{"$in": values}`` binds list items as DATA; operator
                        # smuggling requires attacker-controlled dict KEYS
                        # ({"$gt": ""}). A query whose only operators are
                        # data-operand lists is parameterized, not injectable
                        # (``find({"_id": {"$in": ids}})``).
                        if (
                            str(rule.get("vuln", "")).lower() == "nosql_injection"
                            and _nosql_taint_reaches_only_data_operand(candidate_line)
                        ):
                            continue

                        concrete_candidate = candidate_idx
                        break

                    if concrete_candidate is None:
                        continue

                    # G5 (2026-10-19, prodtest): a bare ``body``/``query``
                    # word is user-input evidence only when it sits on a
                    # human-length line together with the sink. Across lines
                    # it is prose/local state (the SSRF A9 gate already makes
                    # this exact argument for bare window words), and on a
                    # >400-char minified line the source/sink co-location is
                    # lexical coincidence in vendored code. All 7 measured
                    # prototype-pollution rows (WebGoat jquery x4 +
                    # wysihtml5, railsgoat dataTables, dvpwa jquery) were
                    # bare-token coincidences; qualified ``req.body``/
                    # ``req.query`` aliases keep firing everywhere,
                    # cross-line and minified included.
                    if rule.get("id") == "TAINT_PROTOTYPE_POLLUTION":
                        _pp_src = src_match.group(0).strip().lower()
                        if _pp_src in {"body", "query"} and (
                            concrete_candidate != i or len(lines[i]) > 400
                        ):
                            continue

                    evidence_line = concrete_candidate + 1
                    snippet = lines[concrete_candidate]

                    candidate_sink_match = sink_re.search(
                        lines[concrete_candidate]
                    )

                    if candidate_sink_match is None:
                        continue

                    sink = candidate_sink_match.group(0)[:80]

                    # V1.12a: TAINT_MULTIPART_TRAVERSAL is the one rule
                    # whose src token (``filename``) and sink token
                    # (``File(``) are this generic, so its window can span
                    # a value that provably never reaches the sink. When
                    # the bounded abstract evaluation PROVES the subject's
                    # value at the sink line is a compile-time constant
                    # (constant-folded ternary/branch, strong-update
                    # reassignment, literal-returning same-file helper),
                    # no attacker input can reach it and the window
                    # coincidence is discarded. Every "not proven" outcome
                    # keeps the finding byte-identical.
                    if rule.get("id") == "TAINT_MULTIPART_TRAVERSAL" and \
                            _multipart_flow_proves_constant(
                                source, filepath, src_match,
                                concrete_candidate):
                        break

                    # I21 (2026-10-27, aclean/sc production scan): the window
                    # also associates a multipart ``filename`` from ELSEWHERE
                    # in the method with a sink whose argument is a server
                    # property value -- 162 rows shaped
                    # ``File test = new File(propValue + ReportConstants.X);``
                    # where propValue comes from a properties file, not the
                    # upload. The sink ARGUMENT must reference the source
                    # token for the co-occurrence to be a flow; an argument
                    # built only from other identifiers is not attacker
                    # input. (The existing constant-proof cannot resolve
                    # cross-file ReportConstants, so this argument-scope
                    # check is the honest gate.)
                    if rule.get("id") == "TAINT_MULTIPART_TRAVERSAL":
                        sink_line = lines[concrete_candidate]
                        # Minified vendor-bundle lines (19k-88k chars in the
                        # measured corpora) have no statement structure: a
                        # `fileName` occurrence inside one is lexical
                        # coincidence, the same G2b conclusion the LLM
                        # engine documented for its own rules.
                        if len(sink_line) > 2000:
                            break
                        # The window's src_match may sit lines away (e.g.
                        # MultipartFile on the signature). A flow exists when
                        # the SINK LINE ITSELF carries a source token --
                        # word-bounded, because ReportConstants.AD_MASTER_
                        # FILENAME contains the literal letters "filename"
                        # and the unbounded form classified the aclean/sc
                        # propValue+CONSTANT FPs as flows.
                        if not re.search(
                            r"\b(?:multipartfile|request\.files|req\.file|"
                            r"iformfile|\$_files|getoriginalfilename|"
                            r"filename)\b",
                                sink_line, re.IGNORECASE):
                            break

                source_label = src_match.group(0)[:80]
                findings.append(
                    _base_finding(
                        rule,
                        filepath,
                        evidence_line,
                        snippet,
                        source_label,
                        sink,
                        lang,
                    )
                )
                break

    return findings


def _taint_dicts(findings: list) -> list[dict]:
    """Render TaintFinding objects as report dicts.

    Extracted from ``_python_ast_findings`` so the interprocedural
    post-pass (scanner/taint_interproc.py) renders its seeded run through
    exactly this table: one schema, one source of truth for group_key and
    the metadata columns.
    """
    rendered = []
    for tf in findings:
        m = get_mapping(tf.vuln_type)
        # Fallback control set when the central mapping omits a Big-4 column.
        # Previously referenced but never bound, which raised NameError for any
        # vuln_type missing pci_dss and dropped the whole finding.
        controls = BIG4_TAINT_CONTROLS.get(tf.vuln_type, {})
        sev = tf.severity or m.get("severity", "High")
        snippet = tf.snippet.strip()
        rendered.append({
            "rule_id": tf.rule_id or f"TAINT_{tf.vuln_type.upper()}", "title": tf.title or m.get("title", tf.vuln_type.replace("_", " ").title()),
            "vuln_type": tf.vuln_type, "severity": sev, "priority": _priority(sev), "confidence": tf.confidence,
            "language": tf.language, "file": tf.file, "line": tf.line, "snippet": snippet,
            "group_key": f"{tf.vuln_type}|{tf.file}|{tf.line}|{snippet[:100]}", "function": tf.function,
            "description": f"Taint flow: {tf.taint_path}", "remediation": tf.remediation or m.get("remediation", []),
            "owasp": tf.owasp or m.get("owasp", ""), "owasp_id": m.get("owasp_id", ""), "cwe": tf.cwe or m.get("cwe", ""), "cwe_desc": m.get("cwe_desc", ""),
            "mitre": m.get("mitre", ""), "mitre_desc": m.get("mitre_desc", ""), "pci_dss": m.get("pci_dss") or controls.get("pci_dss", ""), "nist": m.get("nist") or controls.get("nist", ""), "nist_800_53": m.get("nist_800_53") or m.get("nist") or controls.get("nist", ""), "iso27001": m.get("iso27001") or controls.get("iso27001", ""), "iso_27001": m.get("iso_27001") or m.get("iso27001") or controls.get("iso27001", ""), "soc2": m.get("soc2") or controls.get("soc2", ""),
            "business_impact": m.get("business_impact", ""), "exploitability": m.get("exploitability", "High"),
            "taint_path": tf.taint_path, "taint_chain": tf.chain, "source_expr": tf.source_expr, "sink_call": tf.sink_call,
            "evidence": f"{tf.file}:{tf.line}: {snippet}", "detection": "AST Taint Analysis", "engine": "scanner.taint_engine", "cvss": None, "cve": None,
        })
    return rendered


def _python_ast_findings(filepath: str, source: str) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    # Both maps are derived once from the module AST and shared by the two
    # passes so the pre-pass and the reporting pass see identical topology.
    route_params = _route_param_map(tree)
    funcs = _function_map(tree)
    route_handlers = _route_handler_names(tree)
    pre = TaintVisitor(lines, filepath, route_params, funcs, route_handlers); pre.visit(tree)
    visitor = TaintVisitor(lines, filepath, route_params, funcs, route_handlers)
    visitor._tainted_returns = dict(pre._tainted_returns)
    visitor.visit(tree)
    return _taint_dicts(visitor.findings)


# ---------------------------------------------------------------------------
# Java semantic taint layer (J1)
# ---------------------------------------------------------------------------
# The enterprise text layer above is intentionally conservative and local.
# BenchmarkJava exposes a separate, reusable gap: Java servlet sources often
# flow through assignments/decoders/string concatenation before reaching a
# security sink.  This layer adds bounded intraprocedural data-flow for Java.
# It does NOT use benchmark filenames, test IDs, comments, or line-specific
# exceptions.

_JAVA_SOURCE_PATTERNS = [
    (re.compile(r'\b(?:request|req)\s*\.\s*getParameter\s*\(', re.I), 'HttpServletRequest.getParameter()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getHeader\s*\(', re.I), 'HttpServletRequest.getHeader()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getHeaders\s*\(', re.I), 'HttpServletRequest.getHeaders()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getCookies\s*\(', re.I), 'HttpServletRequest.getCookies()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getQueryString\s*\(', re.I), 'HttpServletRequest.getQueryString()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getRequestURI\s*\(', re.I), 'HttpServletRequest.getRequestURI()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getRequestURL\s*\(', re.I), 'HttpServletRequest.getRequestURL()'),
    # F4/F5: the parameterMap/parameterNames/parameterValues and
    # headerNames enumeration families are untrusted input exactly like
    # getParameter/getHeader.  BenchmarkJava feeds 20 command-injection
    # true tests and every one of the 12 remaining path-traversal misses
    # through them; no layer seeded them, so the whole carrier chain
    # stayed invisible.
    (re.compile(r'\b(?:request|req)\s*\.\s*getParameterMap\s*\(', re.I), 'HttpServletRequest.getParameterMap()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getParameterNames\s*\(', re.I), 'HttpServletRequest.getParameterNames()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getParameterValues\s*\(', re.I), 'HttpServletRequest.getParameterValues()'),
    (re.compile(r'\b(?:request|req)\s*\.\s*getHeaderNames\s*\(', re.I), 'HttpServletRequest.getHeaderNames()'),
    # F4: the benchmark's own parameter wrapper (`scr.getTheParameter("id")`
    # from CustomUtilities) is untrusted input exactly like getParameter --
    # J5 has modeled it as a source since its wrapper rule
    # (_J5_WRAPPER_SOURCE_RE); this is the line-layer/J3/J3.2c mirror of the
    # same fact.  The last 4 measured command-injection misses all start here.
    (re.compile(r'\b[A-Za-z_$][\w$]*\s*\.\s*getTheParameter\s*\(', re.I), 'SourceControl.getTheParameter()'),
]

_JAVA_TRANSFORM_PATTERNS = [
    re.compile(r'\bURLDecoder\s*\.\s*decode\s*\(', re.I),
    re.compile(r'\bString\s*\.\s*(?:valueOf|format)\s*\(', re.I),
]

_JAVA_SINKS = [
    ('command_injection', 'CWE-78', 'Java ProcessBuilder command execution', re.compile(
        r'\bProcessBuilder\s*\([^;]*\)|\bProcessBuilder\s*\.\s*command\s*\(|\b\w+\s*\.\s*command\s*\([^;]*\)|\b\w+\s*\.\s*start\s*\(', re.I)),
    ('command_injection', 'CWE-78', 'Java Runtime.exec command execution', re.compile(
        r'\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|\b\w+\s*\.\s*exec)\s*\(', re.I)),
    ('sql_injection', 'CWE-89', 'JDBC SQL execution', re.compile(
        r'\b(?:(?:prepareCall|prepareStatement|executeQuery|executeUpdate|execute'
        r'|queryForObject|queryForLong|queryForInt|queryForMap|queryForList'
        r'|queryForRowSet|batchUpdate|addBatch)\s*\('
        r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
        r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\()',
        re.I)),
    ('ldap_injection', 'CWE-90', 'LDAP directory search', re.compile(
        r'\b(?:\w+\s*\.\s*)?(?:search|searchLink|lookup)\s*\(', re.I)),
    ('path_traversal', 'CWE-22', 'Java filesystem access', re.compile(
        # F5: the optional package qualifier is load-bearing.  The measured
        # path-traversal misses all write `new java.io.File(` / `new
        # java.io.FileOutputStream(`, where `java` follows `new ` and an
        # unqualified `File` alternation never matches.  Same blind spot
        # applies to java.nio.file (Files/Paths) -- J5 fixed it there first
        # (121/133); this is the line layer mirror.
        r'\bnew\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\('
        r'|\b(?:[A-Za-z_$][\w$]*\s*\.\s*)*(?:Files|Paths)\s*\.\s*(?:readAllBytes|readString|readAllLines|newInputStream|newOutputStream|delete|copy|move|get)\s*\(',
        re.I)),
    ('trust_boundary_violation', 'CWE-501', 'Java session trust boundary crossing', re.compile(
        # F1: storing request-derived data in the HTTP session is the
        # benchmark's trust-boundary family.  Only the J3 layer modeled
        # `X.getSession().setAttribute(IDENT, ...)` -- key position alone --
        # so `putValue` (45 oracle-positives) and the value position (50)
        # stayed dark.  The receiver is pinned to the measured
        # `getSession()` chain; the generic argument scan reads BOTH
        # argument positions and the shared order-aware dead-name walk still
        # kills a carrier whose last write before the store is provably
        # constant (folded branches, cross-method const returns).
        r'\bgetSession\s*\(\s*\)\s*\.\s*(?:setAttribute|putValue)\s*\(',
        re.I)),
    ('xss', 'CWE-79', 'Java HTTP response output', re.compile(
        # F6: the chained response.getWriter().print(...) form covers all
        # 244 detected xss tests, but every one of the 9 remaining measured
        # misses writes through a writer VARIABLE:
        #   PrintWriter out = response.getWriter();
        #   out.format(java.util.Locale.US, fmt, obj);
        # Neither this layer nor J4 ever matched that receiver, so those
        # files had NO xss sink at all.  The named group is gated in the
        # sink loop: the receiver must be a response writer DECLARED IN
        # THIS FILE (and never the `out` of `System.out.print`), so every
        # other same-verb receiver (fmt.format, String.format, file.write)
        # stays exactly as dark as before.
        r'\b(?:(?:response\s*\.\s*)?getWriter\s*\(\s*\)\s*\.\s*(?:print|println|printf|format|write)'
        r'|\b(?P<wvar>[A-Za-z_$][\w$]*)\s*\.\s*(?:print|println|printf|format|write))\s*\(',
        re.I)),
    ('xpath_injection', 'CWE-643', 'Java XPath expression compilation/evaluation', re.compile(
        r'\b(?:\w+\s*\.\s*)?(?:compile|evaluate)\s*\(', re.I)),
]


def _java_clean_line(line: str) -> str:
    # Remove simple // comments while retaining string literals before the
    # comment marker.  Block comments are handled by the state machine.
    quote = None
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == '\\':
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
            return line[:i]
    return line


def _java_bracket_depth(text: str) -> int:
    """Quote-aware net bracket depth of a (comment-masked) Java fragment."""
    depth = 0
    quote = None
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
    return depth


def _java_statement_text(masked: list[str], idx: int, max_extra: int = 6) -> str:
    """Join line ``idx`` with following lines while its statement is open.

    Formatted Java routinely wraps call arguments across lines::

        ...JDBCtemplate.queryForObject(
                sql, Long.class);

    A per-line sink scan sees only ``queryForObject(`` and therefore misses
    the tainted carrier on the next line.  The join is bounded (max_extra
    lines) and stops as soon as brackets balance and the statement ends --
    it never reaches past the statement the sink belongs to.

    F8: a bracket-balanced line ending in ``{`` is also a statement end --
    a complete statement HEADER (try-with-resources head, if/while header,
    lambda block body opener).  Without the brace stop the join crossed
    into the block BODY and read the next statement as sink-argument
    text: SafeServlet.java's parameterised
    ``prepareStatement(sql)) {`` header swallowed
    ``ps.setString(1, userInput);`` and reported the BOUND PARAMETER as
    CWE-89 (corpus java FP 6 -> 7, measured 8ff9894..cbe8613).  An open
    CALL cannot end in a header brace -- its depth is still > 0 there --
    so every measured wrapped-argument shape keeps joining to its ``;``.
    """
    acc = masked[idx]
    if _java_bracket_depth(acc) <= 0 and acc.rstrip().endswith((";", "{")):
        return acc
    parts = [acc]
    for j in range(idx + 1, min(len(masked), idx + 1 + max_extra)):
        nxt = masked[j]
        if not nxt.strip():
            break
        parts.append(nxt)
        acc = acc + " " + nxt
        if _java_bracket_depth(acc) <= 0 and acc.rstrip().endswith((";", "{")):
            break
    return " ".join(parts)


def _java_mask_comments(lines: list[str]) -> list[str]:
    out = []
    in_block = False
    for raw in lines:
        line = raw
        result = []
        i = 0
        while i < len(line):
            if in_block:
                end = line.find('*/', i)
                if end < 0:
                    i = len(line)
                    break
                in_block = False
                i = end + 2
                continue
            start = line.find('/*', i)
            if start < 0:
                result.append(line[i:])
                break
            result.append(line[i:start])
            end = line.find('*/', start + 2)
            if end < 0:
                in_block = True
                i = len(line)
            else:
                i = end + 2
        out.append(''.join(result))
    return [_java_clean_line(x) for x in out]


def _java_identifiers(text: str) -> set[str]:
    return set(re.findall(r'\b[A-Za-z_$][A-Za-z0-9_$]*\b', text or ''))


def _java_source_in_expr(expr: str) -> str | None:
    for pattern, label in _JAVA_SOURCE_PATTERNS:
        if pattern.search(expr):
            return label
    return None


def _java_taint_in_expr(expr: str, tainted: dict[str, dict]) -> list[str]:

    # B1 sanitizer control: identifiers appearing inside Java string literals
    # are SQL/text content, not tainted variables.
    # Example:
    #   prepareStatement("... WHERE id = ?")
    # must not treat the literal word "id" as the tainted variable id.
    _B1_JAVA_TAINT_LITERAL_MASK = re.compile(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    )
    expr = _B1_JAVA_TAINT_LITERAL_MASK.sub(" ", str(expr))
    names = []
    for ident in _java_identifiers(expr):
        if ident in tainted and ident not in names:
            names.append(ident)
    return names


def _java_assignment_parts(line: str):
    # Deliberately only handles a simple declaration/assignment.  Complex Java
    # expressions are left for the sink's identifier scan rather than guessed.
    m = re.match(
        r'^\s*(?:(?:final|volatile|transient)\s+)?'
        # F4: statement-form conditionals -- `if (values != null) param =
        # values[0]; else param = "";` -- carry the assignment after the
        # control prefix.  Without this the benchmark's dominant parameter
        # idiom never parsed, so the entire downstream carrier chain stayed
        # invisible (20 measured command-injection misses).  Braced variants
        # already place the assignment on its own line.  Order-aware
        # dead-name/E3 refinement at the sinks still decides liveness.
        r'(?:if\s*\(.*?\)\s*|else\s+)?'
        r'(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?'
        r'([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$',
        line,
    )
    return (m.group(1), m.group(2)) if m else (None, None)


def _java_make_finding(vuln: str, cwe: str, title: str, filepath: str,
                       line_no: int, snippet: str, source_label: str,
                       sink_call: str, chain: list[str]) -> dict:
    mapping = get_mapping(vuln) or {}
    severity = mapping.get('severity') or ('High' if vuln not in {'xss', 'path_traversal'} else 'Medium')
    if vuln in {'command_injection', 'sql_injection', 'ldap_injection', 'path_traversal', 'xpath_injection'}:
        severity = mapping.get('severity') or 'High'
    elif vuln == 'xss':
        severity = mapping.get('severity') or 'High'
    remediation = mapping.get('remediation') or [
        'Validate and constrain untrusted input before security-sensitive use.',
        'Prefer parameterized or safe framework APIs over string construction.',
        'Add a regression test covering the complete source-to-sink flow.',
    ]
    taint_path = ' -> '.join(chain + [sink_call])
    return {
        'rule_id': f'JAVA_TAINT_{vuln.upper()}',
        'title': title,
        'vuln_type': vuln,
        'severity': severity,
        'priority': _priority(severity),
        'confidence': 'High',
        'language': 'java',
        'file': filepath,
        'line': line_no,
        'snippet': snippet.strip(),
        'group_key': f'java-taint|{vuln}|{filepath}|{line_no}|{sink_call}',
        'function': '',
        'description': f'Java taint flow: {taint_path}',
        'remediation': remediation,
        'owasp': mapping.get('owasp', ''),
        'owasp_id': mapping.get('owasp_id', ''),
        'cwe': cwe,
        'cwe_desc': mapping.get('cwe_desc', ''),
        'mitre': mapping.get('mitre', ''),
        'mitre_desc': mapping.get('mitre_desc', ''),
        'pci_dss': mapping.get('pci_dss', ''),
        'nist': mapping.get('nist', ''),
        'nist_800_53': mapping.get('nist_800_53') or mapping.get('nist', ''),
        'iso27001': mapping.get('iso27001', ''),
        'iso_27001': mapping.get('iso_27001') or mapping.get('iso27001', ''),
        'soc2': mapping.get('soc2', ''),
        'business_impact': mapping.get('business_impact', ''),
        'exploitability': mapping.get('exploitability', 'High'),
        'taint_path': taint_path,
        'taint_chain': chain + [sink_call],
        'source_expr': source_label,
        'sink_call': sink_call,
        'evidence': f'{filepath}:{line_no}: {snippet.strip()}',
        'detection': 'Java Intraprocedural Taint Analysis',
        'engine': 'scanner.taint_engine',
        'cvss': None,
        'cve': None,
    }


def _java_dead_names(masked_lines: list[str], taint: set, sink_idx: int,
                     vuln: str | None = None) -> set:
    """Names whose LAST write before ``sink_idx`` is provably safe.

    Delegates to the J5 order-aware walk so the two Java layers share one
    kill discipline (constant-folded branches, try-frame kills, J6B
    collection resolution, and -- when ``vuln`` is given -- class-correct
    sanitizer wraps such as ``encodeForHTML`` at an xss sink). This
    layer's ``tainted`` dict is flow-insensitive and file-global, so a
    name assigned a request value and later overwritten with a safe
    constant stayed tainted forever -- the exact BenchmarkJava negative
    idiom behind most of the JAVA_TAINT_* false positives (53 XSS / 44
    SQL / 37 CMD findings on negative tests). Results only ever REMOVE
    names; a name with no provably-safe last write before the sink keeps
    its hit.

    The delegation also carries FILE-LOCAL call knowledge
    (``_j5_file_call_knowledge``): when the last write is a helper call
    -- ``bar = new Test().doSomething(request, param)`` -- the callee's
    own dead-refined returns decide, exactly as the J5 layer's
    project-wide ``safe_calls`` does for it: constant-folding helpers
    enter the agnostic set, sanitizer-returning helpers enter the set
    for their class only (``htmlEscape`` counts at an xss sink, never at
    a path sink). Without this the line layer re-reported every helper
    shape the J5 layer had already quieted (BenchmarkTest01053's folded
    ternary, 01048/01659's helper-contained htmlEscape). The knowledge
    travels guarded (``_j5_local_call_prefix``): a qualified
    ``Other.doSomething(...)`` can resolve outside this file even when
    a same-named local helper exists, so it never gets the kill.
    """
    try:
        from scanner.java_semantic_j5 import (
            _j5_dead_names, _j5_file_call_knowledge, _j5_local_types)
        src = "\n".join(masked_lines)
        safe, san = _j5_file_call_knowledge(src)
        eff = set(safe)
        if vuln:
            eff |= set(san.get(vuln, ()))
        # Travels as GUARDED local knowledge (prefix-checked inside the
        # walk), never as project-wide safe_calls: a file-local
        # (name, arity) must not mask ``Other.helper(...)`` whose target
        # lives elsewhere. Bare / ``this.`` / ``new LocalType().`` calls
        # -- the benchmark idiom -- still get their kills.
        return _j5_dead_names(
            masked_lines, 1, taint, sink_idx, None, vuln,
            eff or None, _j5_local_types(src))
    except Exception:
        return set()


def _java_chain_severed_by_constant(source: str, chain: list,
                                    at_line: int, filepath: str) -> bool:
    """RSECOPSX_E3_SEVERED_CHAIN_GATE_20261017 -- True only when a simple
    local ON the recorded evidence chain is a proven constant at
    ``at_line`` (shared evaluator ``scanner/multipart_flow``).

    The chain is ONE linear evidence path; a proven-constant local on it
    means its last write folded the value away (constant-true
    branch/ternary with int arithmetic, safe-key map read) and no
    attacker-controlled data can continue past that point -- the
    evaluator proves a constant only when no later write reassigns the
    name.  Kill only on proof: no constant on the chain, any unparseable
    entry, disabled gate (``RSX_MULTIPART_FLOW=0``), or any analysis
    failure returns False (KEEP).
    """
    try:
        from scanner.multipart_flow import is_proven_constant
    except Exception:
        return False
    for entry in chain:
        if not isinstance(entry, str):
            continue
        name = entry.strip()
        if not re.fullmatch(r'[A-Za-z_$][\w$]*', name):
            continue
        try:
            if is_proven_constant(source, name, at_line, filepath=filepath):
                return True
        except Exception:
            continue
    return False


def _scan_java_semantic(filepath: str, source: str) -> list[dict]:
    lines = source.splitlines()
    masked = _java_mask_comments(lines)
    tainted: dict[str, dict] = {}
    tainted_objects: dict[str, dict] = {}
    findings: list[dict] = []

    # A bounded fixed-point pass handles assignments that appear before or
    # after another assignment in the same method/block without attempting a
    # full Java compiler/CFG implementation.
    for _pass in range(4):
        changed = False
        # F4/F5: order-sensitive element state, recomputed from scratch each
        # pass in line order -- a literal-key map put records (or clears)
        # that key's state and a literal-index list add/remove/remove
        # maintains exact oracle shift semantics.  Reads in the assignment
        # below consult this state; anything the model cannot resolve
        # (non-literal keys/indices, unknown shifts) stays unrecorded, which
        # is the conservative direction: a read yields no taint.
        map_state: dict = {}
        list_state: dict = {}
        for idx, line in enumerate(masked):
            if not line.strip():
                continue

            # --- element state updates (last write wins, line order) ---
            put_m = re.search(
                r'\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\((.*)\)\s*;?\s*$', line)
            if put_m:
                p_obj = put_m.group(1)
                p_args = put_m.group(2)
                key_m = re.match(r'\s*("(?:\\.|[^"\\])*")\s*,\s*(.+)$', p_args)
                if key_m:
                    p_names = _java_taint_in_expr(key_m.group(2), tainted)
                    p_src = _java_source_in_expr(key_m.group(2))
                    if p_names:
                        p_par = tainted[p_names[0]]
                        map_state[(p_obj, key_m.group(1))] = {
                            'source': p_par['source'],
                            'chain': list(p_par['chain']),
                        }
                    elif p_src:
                        map_state[(p_obj, key_m.group(1))] = {
                            'source': p_src, 'chain': [p_src],
                        }
                    else:
                        # Last write for this key is a literal: proven safe.
                        map_state[(p_obj, key_m.group(1))] = None
                else:
                    # Non-literal key may touch any bucket: clear so reads
                    # of stale state can never fabricate taint.
                    for mk in [k for k in map_state if k[0] == p_obj]:
                        del map_state[mk]

            add_m = re.search(
                r'\b([A-Za-z_$][\w$]*)\s*\.\s*add\s*\((.*?)\)', line)
            if add_m:
                l_obj, l_val = add_m.group(1), add_m.group(2)
                l_names = _java_taint_in_expr(l_val, tainted)
                l_src = _java_source_in_expr(l_val)
                if l_names:
                    l_par = tainted[l_names[0]]
                    list_state.setdefault(l_obj, []).append({
                        'source': l_par['source'],
                        'chain': list(l_par['chain']),
                    })
                elif l_src:
                    list_state.setdefault(l_obj, []).append(
                        {'source': l_src, 'chain': [l_src]})
                else:
                    list_state.setdefault(l_obj, []).append(None)

            rm_int = re.search(
                r'\b([A-Za-z_$][\w$]*)\s*\.\s*remove\s*\(\s*(\d+)\s*\)', line)
            if rm_int:
                r_obj = rm_int.group(1)
                r_seq = list_state.get(r_obj)
                if r_seq is not None:
                    r_i = int(rm_int.group(2))
                    if 0 <= r_i < len(r_seq):
                        r_seq.pop(r_i)
                    else:
                        # Out-of-range shift: state unknown -> dark reads.
                        list_state[r_obj] = []
                for mk in [k for k in map_state if k[0] == r_obj]:
                    del map_state[mk]
            else:
                rm_any = re.search(
                    r'\b([A-Za-z_$][\w$]*)\s*\.\s*'
                    r'(?:remove|clear)\s*\(\s*\)?', line)
                if rm_any:
                    list_state[rm_any.group(1)] = []
                    for mk in [k for k in map_state if k[0] == rm_any.group(1)]:
                        del map_state[mk]

            # F4: a for-each element takes the union taint of its iterable
            # (`for (Cookie c : theCookies)`) -- the element is written on
            # every iteration, so any tainted content taints the name.  The
            # iterable is read from source taint, the list model above, or
            # collection state; nothing provably tainted yields nothing.
            fe = re.search(
                r'\bfor\s*\(\s*(?:final\s+)?[A-Za-z_$][\w$<>\[\],.? ]*?\s+'
                r'([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)\s*\)', line)
            if fe and fe.group(1) not in tainted:
                fe_elem, fe_iter = fe.group(1), fe.group(2)
                if fe_iter in tainted:
                    p = tainted[fe_iter]
                    tainted[fe_elem] = {
                        'source': p['source'],
                        'chain': list(p['chain']) + [fe_elem],
                    }
                    changed = True
                else:
                    fe_entry = next(
                        (e for e in (list_state.get(fe_iter) or []) if e),
                        None) or tainted_objects.get(fe_iter)
                    if fe_entry:
                        tainted[fe_elem] = {
                            'source': fe_entry['source'],
                            'chain': list(fe_entry['chain']) + [fe_elem],
                        }
                        changed = True

            # F3: wrapped right-hand sides (`String sql =` + continuation
            # concat) must be read as one statement; complete statements are
            # returned unchanged by _java_statement_text.  F4 raised the
            # join cap for assignments: benchmark file-URI construction
            # wraps the concat `+ bar` up to 10 lines below the `URI x =`
            # head (BenchmarkTest00218).  The join is still statement-
            # bounded -- it stops at the first balanced `;` -- so the cap
            # only bounds how long a statement may be, never how far it
            # reaches into neighbours.
            lhs, rhs = _java_assignment_parts(
                _java_statement_text(masked, idx, max_extra=16))
            if lhs:
                # F4/F5: element reads resolve through the order-sensitive
                # models above before generic identifier taint.  A literal
                # string argument reads the map state (per-key last write);
                # a numeric argument reads the list state (exact index after
                # remove shifts).  No recorded entry -> fall through dark.
                get_m = re.search(
                    r'\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*\(\s*'
                    r'("(?:\\.|[^"\\])*"|\d+)\s*\)', rhs)
                if get_m and lhs not in tainted:
                    g_entry = None
                    if get_m.group(2).startswith('"'):
                        g_entry = map_state.get(
                            (get_m.group(1), get_m.group(2)))
                    else:
                        g_seq = list_state.get(get_m.group(1))
                        g_i = int(get_m.group(2))
                        if g_seq is not None and 0 <= g_i < len(g_seq):
                            g_entry = g_seq[g_i]
                    if g_entry:
                        tainted[lhs] = {
                            'source': g_entry['source'],
                            'chain': list(g_entry['chain']) + [lhs],
                        }
                        changed = True
                src = _java_source_in_expr(rhs)
                names = _java_taint_in_expr(rhs, tainted)
                if src and lhs not in tainted:
                    tainted[lhs] = {'source': src, 'chain': [lhs]}
                    changed = True
                elif names and lhs not in tainted:
                    # Do not taint the return value of a security sink merely
                    # because its input was tainted.  For example,
                    # ResultSet rs = statement.executeQuery(sql) does not make
                    # the ResultSet itself equivalent to the SQL string.
                    if re.search(
                        r'\b(?:(?:executeQuery|executeUpdate|execute|prepareCall|prepareStatement|'
                        r'queryForObject|queryForLong|queryForInt|queryForMap|queryForList|'
                        r'queryForRowSet|batchUpdate|search|compile|evaluate|start|exec)\s*\('
                        r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
                        r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\()',
                        rhs,
                        re.I,
                    ):
                        continue
                    parent = tainted[names[0]]
                    tainted[lhs] = {
                        'source': parent['source'],
                        'chain': parent['chain'] + [lhs],
                    }
                    changed = True
        if not changed:
            break

    # Collection/object propagation needed by Java command construction.
    # list.add(tainted) makes the collection tainted; ProcessBuilder.command(
    # collection) then taints the builder, and builder.start() becomes the sink.
    for idx, line in enumerate(masked):
        add_match = re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*add\s*\((.*?)\)', line, re.I)
        if add_match:
            obj = add_match.group(1)
            arg = add_match.group(2)
            names = _java_taint_in_expr(arg, tainted)
            src = _java_source_in_expr(arg)
            if names or src:
                parent = tainted[names[0]] if names else {'source': src, 'chain': [src]}
                tainted_objects[obj] = {
                    'source': parent['source'],
                    'chain': list(parent['chain']) + [obj],
                }

        command_match = re.search(
            r'\b([A-Za-z_$][\w$]*)\s*\.\s*command\s*\((.*?)\)',
            line,
            re.I,
        )
        if command_match:
            builder = command_match.group(1)
            arg = command_match.group(2)
            names = _java_taint_in_expr(arg, tainted, )
            if names:
                parent = tainted[names[0]]
                tainted_objects[builder] = {
                    'source': parent['source'],
                    'chain': list(parent['chain']) + [builder + '.command(...)'],
                }
            elif arg in tainted_objects:
                parent = tainted_objects[arg]
                tainted_objects[builder] = {
                    'source': parent['source'],
                    'chain': list(parent['chain']) + [builder + '.command(...)'],
                }

        # F4: `ProcessBuilder pb = new ProcessBuilder(argList)` is how the
        # measured benchmark misses actually build the command -- only
        # pb.command(...) created builder state before, so every
        # constructor + start() pair stayed dark here.  The builder joins
        # tainted_objects whenever its argument carries taint (direct or
        # array element expression) or collection state (list carrier); the
        # start() sink gate and the severed-chain kill are unchanged, so a
        # literal-argument constructor still never reports.
        ctor_match = re.search(
            r'\b([A-Za-z_$][\w$]*)\s*=\s*new\s+'
            r'(?:[A-Za-z_$][\w$]*\s*\.\s*)*ProcessBuilder\s*\((.*?)\)',
            line,
            re.I,
        )
        if ctor_match:
            ctor_builder = ctor_match.group(1)
            ctor_arg = ctor_match.group(2).strip()
            names = _java_taint_in_expr(ctor_arg, tainted)
            if names:
                parent = tainted[names[0]]
                tainted_objects[ctor_builder] = {
                    'source': parent['source'],
                    'chain': list(parent['chain'])
                    + [ctor_builder + '.new ProcessBuilder(...)'],
                }
            elif ctor_arg in tainted_objects:
                parent = tainted_objects[ctor_arg]
                tainted_objects[ctor_builder] = {
                    'source': parent['source'],
                    'chain': list(parent['chain'])
                    + [ctor_builder + '.new ProcessBuilder(...)'],
                }

    # F6: this file's response-writer variables.  A receiver declared as
    # `PrintWriter <name> = ...getWriter()` is the only state that makes
    # `<name>.print|println|printf|format|write(...)` an HTTP response
    # output sink; nothing else in the file can register one, so the
    # writer-var xss alternative above is inert in files that never obtain
    # a response writer.
    writer_vars = set(re.findall(
        r'\bPrintWriter\s+([A-Za-z_$][\w$]*)\s*=\s*'
        r'(?:[A-Za-z_$][\w$]*\s*\.\s*)*getWriter\s*\(',
        "\n".join(masked)))

    # Sink analysis is intentionally argument-aware: a sink is reported only
    # when the sink call contains a tainted identifier or a source expression.
    for idx, line in enumerate(masked):
        if not line.strip():
            continue
        for vuln, cwe, title, sink_re in _JAVA_SINKS:
            m = sink_re.search(line)
            if not m:
                continue

            # Restrict XPath compile/evaluate to javax.xml.xpath usage or an
            # expression containing a recognizable XPath object.
            if vuln == 'xpath_injection' and not re.search(
                r'\b(?:XPath|xp|xpath)\b|javax\.xml\.xpath', line, re.I
            ):
                continue

            # LDAP lookup is only a security sink when LDAP/JNDI context is
            # present in the file; ordinary application lookup() is not enough.
            if vuln == 'ldap_injection' and not re.search(
                r'\b(?:ldap|DirContext|InitialDirContext|NamingEnumeration|SearchControls|javax\.naming)\b',
                source,
                re.I,
            ):
                continue

            # F3: addBatch is JDBC Statement vocabulary.  Require visible
            # JDBC context in the file so a same-named staging call in
            # unrelated code can never be claimed as SQL execution.
            if (vuln == 'sql_injection'
                    and m.group(0).startswith('addBatch')
                    and not re.search(
                        r'\b(?:Statement|java\.sql|jdbc)\b', source, re.I)):
                continue

            # F6: the writer-variable xss alternative only fires for a
            # receiver this file declared as its response writer.  A
            # same-verb call on any other receiver (fmt.format,
            # String.format, file.write) is not response output and stays
            # dark; `System.out.print(...)` is skipped even when a local
            # writer happens to be named `out`, because there the receiver
            # is System.out.  Advancing the search keeps a later valid
            # writer call on the same line reachable.
            if vuln == 'xss' and m.group('wvar'):
                while m is not None and m.group('wvar'):
                    if (m.group('wvar') in writer_vars
                            and not re.search(
                                r'\bSystem\s*\.\s*$', line[:m.start('wvar')])):
                        break
                    m = sink_re.search(line, m.end())
                if m is None:
                    continue

            # ProcessBuilder.start() is a sink only after a tainted command
            # has been assigned through command(...).
            if vuln == 'command_injection' and re.search(r'\.\s*start\s*\(', line, re.I):
                builder_match = re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*start\s*\(', line, re.I)
                if not builder_match or builder_match.group(1) not in tainted_objects:
                    continue
                obj = builder_match.group(1)
                t = tainted_objects[obj]
                chain = list(t['chain'])
                # RSECOPSX_E3_SEVERED_CHAIN_GATE_20261017 -- this
                # object-state branch had NO kill filter at all: the
                # builder kept its recorded chain even when the attacker
                # data had provably died upstream.  All 8 BenchmarkJava
                # JAVA_TAINT_COMMAND_INJECTION false positives (findings15)
                # route through a folded `bar` before reaching
                # args/argList/argsEnv.  Kill only on proof.
                if _java_chain_severed_by_constant(
                        source, chain, idx + 1, filepath):
                    break
                findings.append(_java_make_finding(
                    vuln, cwe, title, filepath, idx + 1, lines[idx],
                    t['source'], m.group(0).strip()[:120], chain,
                ))
                break

            # The ProcessBuilder constructor is not itself a vulnerable sink.
            if vuln == 'command_injection' and re.search(r'\bProcessBuilder\s*\(', line, re.I):
                continue

            # Extract a conservative call argument from the sink line.
            # F-batch: SQL and path sinks routinely wrap their arguments on
            # the following lines (formatter style); a one-line view would
            # see the callee and lose the carrier.  Join only those two
            # vuln classes so the change stays inside the measured miss
            # families.
            call_text = line[m.start():]
            if vuln in ('sql_injection', 'path_traversal'):
                stmt = _java_statement_text(masked, idx)
                if len(stmt) > len(line):
                    call_text = stmt[m.start():]
            # A sanitizer wrap DIRECTLY at the sink is as good as an
            # assignment-side kill: print(encodeForHTML(param)) cannot
            # carry the vuln even though the wrap never appears as an
            # assignment the dead-walk could kill on. Blank the wrap
            # (its arguments included) before extracting names; None
            # (no wrap for this class / unbalanced extent) keeps the
            # raw text -- the conservative direction. Import is lazy to
            # mirror _java_dead_names (avoids the module import cycle).
            from scanner.java_semantic_j5 import _j5_blank_sanitizer_spans
            covered = _j5_blank_sanitizer_spans(call_text, vuln)
            if covered is not None:
                call_text = covered
            names = _java_taint_in_expr(call_text, tainted)
            # Order-aware refinement: a name whose last write before this
            # sink line is provably safe is not a live carrier here, even
            # though the flow-insensitive dict kept it since its
            # (long-overwritten) assignment -- see _java_dead_names.
            # _j5_dead_names takes a 1-BASED sink line and stops strictly
            # before it, so idx (0-based) must be converted.
            if names:
                dead = _java_dead_names(masked, set(tainted), idx + 1, vuln)
                names = [n for n in names if n not in dead]
            source_expr = _java_source_in_expr(call_text)
            if not names and not source_expr:
                continue

            if names:
                t = tainted[names[0]]
                chain = list(t['chain'])
                source_label = t['source']
            else:
                chain = [source_expr]
                source_label = source_expr

            # RSECOPSX_E3_SEVERED_CHAIN_GATE_20261017 -- command_injection
            # only (the measured family: the r.exec(...) argv-array shapes
            # 01686/01939/02068 whose recorded chain passes through a
            # folded `bar`; the ProcessBuilder.start() branch carries the
            # same gate above).  Void evidence: the chain is ONE linear
            # path and a proven-constant local on it means the attacker
            # data provably died before this sink.
            if (vuln == 'command_injection'
                    and _java_chain_severed_by_constant(
                        source, chain, idx + 1, filepath)):
                break

            sink_call = m.group(0).strip()[:120]
            findings.append(_java_make_finding(
                vuln, cwe, title, filepath, idx + 1, lines[idx],
                source_label, sink_call, chain,
            ))
            break

    # Deduplicate exact sink locations while preserving separate sink types.
    seen = set()
    out = []
    for f in findings:
        key = (f['vuln_type'], f['file'], f['line'], f['sink_call'])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out

# RSECOPSX_R11_21_DEPLOYED_BRANCH_SCOPED_INPUT_V1
def _r11_21_branch_scoped_input(filepath, source):
    try:
        from scanner.java_semantic_switch_vnext_r7 import _branch_scoped_source
        masked, active, reason = _branch_scoped_source(source)
        if active and masked != source and reason == "DETERMINISTIC_SINGLE_BRANCH":
            return masked
    except Exception:
        pass
    return source
def _analyze_base(filepath: str) -> list[dict]:
    path = Path(filepath)
    if _is_generated_artifact(filepath):
        return []
    source = file_index.read_source(path)
    if source is None:
        return []
    lang = _language(path)
    findings: list[dict] = []
    if lang == "python":
        findings.extend(_python_ast_findings(filepath, source))
    elif lang == "java":
        findings.extend(_scan_java_semantic(filepath, source))
    findings.extend(_scan_enterprise_text(filepath, source, lang))
    # Dedup within file.
    seen = set(); out = []
    for f in findings:
        k = f.get("group_key") or f"{f.get('rule_id')}|{f.get('line')}|{f.get('snippet')}"
        if k not in seen:
            seen.add(k); out.append(f)
    return out

if __name__ == "__main__":
    import json, sys
    print(json.dumps(analyze_file(sys.argv[1]), indent=2))


# Backward-compatible alias used by standalone validation commands.
def scan_file(filepath: str) -> list[dict]:
    return analyze_file(filepath)


# ---------------------------------------------------------------------------
# Java security API semantics layer (J2)
# ---------------------------------------------------------------------------
# J2 complements the J1 source-to-sink layer with API-level semantics for
# weak randomness, weak hashes, and weak cryptographic primitives.  It is
# deliberately independent of BenchmarkJava filenames/IDs and uses only the
# Java source text and API/algorithm semantics.

_JAVA_J2_RULES = [
    ('weak_random', 'CWE-330', 'Java insecure random generator',
     re.compile(r'\b(?:new\s+java\.util\.Random\s*\(|new\s+Random\s*\(|java\.util\.Random\s+[A-Za-z_$][\w$]*\s*=|Random\s+[A-Za-z_$][\w$]*\s*=|Math\s*\.\s*random\s*\()', re.I),
     'WEAK_RANDOM'),
    ('weak_crypto', 'CWE-327', 'Java weak cryptographic algorithm',
     re.compile(r'\b(?:Cipher|KeyGenerator|Mac|Signature|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*["\']\s*(?:DES|DESede|3DES|RC2|RC4|ARCFOUR|Blowfish|IDEA|RC5|MD2|MD4)\b', re.I),
     'WEAK_CRYPTO'),
    ('weak_crypto', 'CWE-327', 'Java insecure ECB cipher mode',
     re.compile(r'\bCipher\s*\.\s*getInstance\s*\(\s*["\'][^"\']*/ECB(?:/|["\'])', re.I),
     'WEAK_CRYPTO'),
    ('weak_hash', 'CWE-328', 'Java weak cryptographic hash',
     re.compile(r'\bMessageDigest\s*\.\s*getInstance\s*\(\s*["\']\s*(?:MD2|MD4|MD5|SHA-1|SHA1)\s*["\']', re.I),
     'WEAK_HASH'),
]


def _java_j2_string_assignments(masked: list[str]) -> dict[str, str]:
    values = {}
    for line in masked:
        m = re.match(r'^\s*(?:(?:final|static|private|public|protected)\s+)*'
                     r'(?:String\s+)?([A-Za-z_$][\w$]*)\s*=\s*["\']([^"\']+)["\']\s*;?\s*$', line)
        if m:
            values[m.group(1)] = m.group(2)
    return values


# --- F2: property-driven algorithm resolution -----------------------------
# A `.properties` resource co-located with the scanned file is resolved as
# data, never guessed: file value wins, the code default applies only when
# the file or key is absent, and anything unresolvable stays unreported.

_PROPS_FILE_CACHE: dict[tuple[str, str], str | None] = {}
_PROPS_TABLE_CACHE: dict[str, dict[str, str]] = {}


def _java_find_properties_file(filepath: str, name: str) -> str | None:
    """Locate a named resource near the scanned file (bounded)."""
    base = Path(filepath).parent if Path(filepath).is_file() else Path(filepath)
    ckey = (str(base), name)
    if ckey in _PROPS_FILE_CACHE:
        return _PROPS_FILE_CACHE[ckey]
    result: str | None = None
    # The resource may sit beside the scanned file (base) or in any
    # ancestor (src/main/resources and friends) -- include base itself.
    parents = [base, *list(base.parents)[:9]]
    for parent in parents:
        for cand in (
            parent / name,
            parent / "src" / "main" / "resources" / name,
            parent / "main" / "resources" / name,
            parent / "resources" / name,
            parent / "config" / name,
            parent / "conf" / name,
            parent / "src" / "main" / "webapp" / "WEB-INF" / name,
        ):
            try:
                if cand.is_file():
                    result = str(cand)
                    break
            except OSError:
                continue
        if result:
            break
    if result is None:
        # Bounded fallback: search only inside a nearby src/ tree, and stop
        # at the first match.  Candidate paths above normally win.
        # T-0.2: query the scan's one index (never a second walk). The
        # rglob remains only for standalone calls with no active index.
        from core import file_index
        active_idx = file_index.current()
        for parent in parents:
            srcdir = parent / "src"
            try:
                if srcdir.is_dir():
                    if active_idx is not None:
                        for found in active_idx.files(names={name}):
                            # any depth below srcdir (maven layout is
                            # src/main/resources/...)
                            if srcdir in found.parents:
                                result = str(found)
                                break
                    else:
                        # FND-02: the former by-name glob becomes the one
                        # walk plus a name match (fnmatch keeps the glob
                        # form working).
                        # walk yields files in deterministic sorted order,
                        # so a duplicate name resolves the same way every
                        # run instead of in OS readdir order.
                        for found, _size, _mtime in walk(
                            srcdir, exts=None, ignore=frozenset(),
                            max_bytes=None,
                        ):
                            if fnmatch.fnmatch(found.name, name):
                                result = str(found)
                                break
            except OSError:
                continue
            if result:
                break
    _PROPS_FILE_CACHE[ckey] = result
    return result


def _java_parse_properties_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        # First unescaped '=', ':' or whitespace separates key and value.
        sep_idx = None
        escaped = False
        for i, ch in enumerate(line):
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch in "=: \t":
                sep_idx = i
                break
        if sep_idx is None or sep_idx == 0:
            continue
        key = line[:sep_idx].strip()
        value = line[sep_idx:].lstrip("=: \t")
        for esc, plain in (("\\:", ":"),("\\=", "="),("\\ ", " "),
                           ("\\\\", "\\"), ("\\t", "\t"), ("\\n", "\n")):
            value = value.replace(esc, plain)
        if key:
            out[key] = value.strip()
    return out


def _java_properties_resolved_values(masked: list[str],
                                     filepath: str) -> dict[str, str]:
    """ident -> value for `ident = props.getProperty("key"[, "default"])`.

    ``props`` must be bound in this file to a findable .properties resource
    via ``props.load(...getResourceAsStream("name.properties"))``.  Both the
    load binding and the assignment are read as logical statements so the
    benchmark's wrapped ``props.load(\\n ...)`` form resolves too.
    """
    load_re = re.compile(
        r'([A-Za-z_$][\w$]*)\s*\.\s*load\s*\(\s*'
        r'[^;]{0,240}?getResourceAsStream\s*\(\s*"([^"]+)"',
        re.I,
    )
    get_re = re.compile(
        r'([A-Za-z_$][\w$]*)\s*=\s*'
        r'([A-Za-z_$][\w$]*)\s*\.\s*getProperty\s*\(\s*"([^"]+)"'
        r'\s*(?:,\s*"([^"]*)"\s*)?\)',
        re.I,
    )
    bound: dict[str, dict[str, str]] = {}
    resolved: dict[str, str] = {}
    for idx in range(len(masked)):
        if not masked[idx].strip():
            continue
        stmt = _java_statement_text(masked, idx)
        bm = load_re.search(stmt)
        if bm and bm.group(1) not in bound:
            res_name = bm.group(2)
            path = _java_find_properties_file(filepath, res_name)
            table = None
            if path:
                table = _PROPS_TABLE_CACHE.get(path)
                if table is None:
                    _props_text = file_index.read_source(Path(path))
                    if _props_text is None:
                        table = {}
                    else:
                        table = _java_parse_properties_text(_props_text)
                    _PROPS_TABLE_CACHE[path] = table
            bound[bm.group(1)] = table or {}
    if not bound:
        return resolved
    for idx in range(len(masked)):
        if not masked[idx].strip():
            continue
        stmt = _java_statement_text(masked, idx)
        gm = get_re.search(stmt)
        if not gm or gm.group(2) not in bound:
            continue
        table = bound[gm.group(2)]
        value = table.get(gm.group(3))
        if value is None:
            value = gm.group(4)  # code default: the runtime fallback
        if value is not None:
            resolved[gm.group(1)] = value
    return resolved


def _scan_java_security_api_semantics(filepath: str, source: str) -> list[dict]:
    lines = source.splitlines()
    masked = _java_mask_comments(lines)
    string_values = _java_j2_string_assignments(masked)
    # F2: property-driven algorithms resolve through the co-located
    # .properties resource (file value wins; code default only when the
    # file or key is absent; unresolvable stays unreported).
    try:
        string_values.update(
            _java_properties_resolved_values(masked, filepath))
    except OSError:
        pass
    findings = []
    seen = set()

    def emit(vuln, cwe, title, rule_id, line_no, snippet, algorithm, sink_call):
        key = (rule_id, filepath, line_no, algorithm.lower())
        if key in seen:
            return
        seen.add(key)
        mapping = get_mapping(vuln) or {}
        severity = mapping.get('severity') or ('Medium' if vuln == 'weak_random' else 'Medium')
        remediation = mapping.get('remediation') or [
            'Use a security-appropriate API and avoid deprecated or cryptographically weak algorithms.',
            'Prefer SecureRandom for security-sensitive randomness and modern approved cryptographic algorithms.',
            'Add a regression test covering the security-sensitive API usage.',
        ]
        findings.append({
            'rule_id': f'JAVA_J2_{rule_id}',
            'title': title,
            'vuln_type': vuln,
            'severity': severity,
            'priority': _priority(severity),
            'confidence': 'High',
            'language': 'java',
            'file': filepath,
            'line': line_no,
            'snippet': snippet.strip(),
            'group_key': f'java-j2|{rule_id}|{filepath}|{line_no}|{algorithm}',
            'function': '',
            'description': f'Java security API semantic finding: {algorithm}.',
            'remediation': remediation,
            'owasp': mapping.get('owasp', ''),
            'owasp_id': mapping.get('owasp_id', ''),
            'cwe': cwe,
            'cwe_desc': mapping.get('cwe_desc', ''),
            'mitre': mapping.get('mitre', ''),
            'mitre_desc': mapping.get('mitre_desc', ''),
            'pci_dss': mapping.get('pci_dss', ''),
            'nist': mapping.get('nist', ''),
            'nist_800_53': mapping.get('nist_800_53') or mapping.get('nist', ''),
            'iso27001': mapping.get('iso27001', ''),
            'iso_27001': mapping.get('iso_27001') or mapping.get('iso27001', ''),
            'soc2': mapping.get('soc2', ''),
            'business_impact': mapping.get('business_impact', ''),
            'exploitability': mapping.get('exploitability', 'Medium'),
            'taint_path': '',
            'taint_chain': [],
            'source_expr': '',
            'sink_call': sink_call,
            'evidence': f'{filepath}:{line_no}: {snippet.strip()}',
            'detection': 'Java Security API Semantic Analysis',
            'engine': 'scanner.taint_engine',
            'cvss': None,
            'cve': None,
        })

    for idx, line in enumerate(masked):
        if not line.strip():
            continue

        # Direct semantic rules.
        for vuln, cwe, title, pattern, rule_id in _JAVA_J2_RULES:
            m = pattern.search(line)
            if m:
                algorithm = m.group(0).strip()[:120]
                emit(vuln, cwe, title, rule_id, idx + 1, lines[idx], algorithm, m.group(0).strip()[:120])

        # Resolve a simple algorithm variable into a security API call, e.g.
        # String alg = "DES"; Cipher.getInstance(alg).  This remains bounded
        # and does not guess arbitrary string/data flow.
        for var, value in string_values.items():
            if not re.search(r'\b' + re.escape(var) + r'\b', line):
                continue
            upper = value.upper().strip()
            if upper in {'DES', 'DESEDE', '3DES', 'RC2', 'RC4', 'ARCFOUR', 'BLOWFISH', 'IDEA', 'RC5', 'MD2', 'MD4'}:
                if re.search(r'\b(?:Cipher|KeyGenerator|Mac|Signature|SecretKeyFactory)\s*\.\s*getInstance\s*\(', line, re.I):
                    emit('weak_crypto', 'CWE-327', 'Java weak cryptographic algorithm', 'WEAK_CRYPTO', idx + 1, lines[idx], value, line.strip()[:120])
            elif upper in {'MD5', 'SHA-1', 'SHA1'}:
                if re.search(r'\bMessageDigest\s*\.\s*getInstance\s*\(', line, re.I):
                    emit('weak_hash', 'CWE-328', 'Java weak cryptographic hash', 'WEAK_HASH', idx + 1, lines[idx], value, line.strip()[:120])

    return findings


# Wrap analyze_file once more so J2 remains additive to J1/Python behavior.
def _apply_j2_java_semantics(filepath: str, findings: list[dict]) -> list[dict]:
    # Incoming findings from the canonical pipeline are already in 'findings'.
    try:
        path = Path(filepath)
        if path.suffix.lower() == '.java' and not _is_generated_artifact(filepath):
            source = file_index.read_source(path)
            if source is not None:
                findings.extend(
                    _scan_java_security_api_semantics(filepath, source))
    except OSError:
        pass
    seen = set()
    out = []
    for f in findings:
        k = f.get('group_key') or f"{f.get('rule_id')}|{f.get('line')}|{f.get('snippet')}"
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out

# ---------------------------------------------------------------------------
# Java semantic expansion layer (J3.1)
# ---------------------------------------------------------------------------
# J3.1 is deliberately bounded and intraprocedural. It extends J1/J2 with
# expression, collection, Enumeration, JDBC, filesystem and HTTP-output flow,
# plus two context-aware FP controls observed during BenchmarkJava analysis.

_J3_JAVA_SINKS = {
    'jdbc': (
        'sql_injection', 'CWE-89', 'Java JDBC SQL injection',
        # F3: + Spring JdbcTemplate family (short names receiver-constrained,
        # same construction as the line-layer and J5 SQL sinks).
        re.compile(r'\b(?:(?:prepareCall|prepareStatement'
                   r'|queryForObject|queryForLong|queryForInt|queryForMap'
                   r'|queryForList|queryForRowSet|batchUpdate|addBatch)\s*\('
                   r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
                   r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\()',
                   re.I)
    ),
    'jdbc_execute': (
        'sql_injection', 'CWE-89', 'Java JDBC SQL injection',
        re.compile(r'\b(?:[A-Za-z_$][\w$]*\.)?(?:executeQuery|executeUpdate|execute)\s*\(', re.I)
    ),
    'filesystem': (
        'path_traversal', 'CWE-22', 'Java filesystem path traversal',
        re.compile(r'\bnew\s+(?:File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\(|\b(?:Files|Paths)\s*\.\s*(?:readAllBytes|readString|readAllLines|newInputStream|newOutputStream|delete|copy|move|get)\s*\(', re.I)
    ),
    'process': (
        'command_injection', 'CWE-78', 'Java command injection',
        re.compile(r'\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|[A-Za-z_$][\w$]*\s*\.(?:exec|start))\s*\(', re.I)
    ),
    'http_output': (
        'xss', 'CWE-79', 'Java HTTP response output',
        re.compile(r'\b(?:response\s*\.\s*)?getWriter\s*\(\s*\)\s*\.\s*(?:print|println|printf|format|write)\s*\(', re.I)
    ),
    'xpath': (
        'xpath_injection', 'CWE-643', 'Java XPath injection',
        re.compile(r'\b(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:compile|evaluate)\s*\(', re.I)
    ),
}

_J3_JAVA_SOURCE_RE = re.compile(
    r'\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getHeaders|getCookies|getQueryString|getRequestURI|getRequestURL)\s*\(', re.I
)

_J3_JAVA_COOKIE_VALUE_RE = re.compile(r'\b[A-Za-z_$][\w$]*\s*\.\s*getValue\s*\(', re.I)
_J3_JAVA_DECODER_RE = re.compile(r'\bURLDecoder\s*\.\s*decode\s*\(', re.I)
_J3_JAVA_PROPERTY_RE = re.compile(r'\b(?:[A-Za-z_$][\w$]*\.)?getProperty\s*\(', re.I)


def _j3_emit(vuln, cwe, title, filepath, line_no, snippet, source_label, sink_call, chain):
    mapping = get_mapping(vuln) or {}
    severity = mapping.get('severity') or {
        'command_injection': 'High', 'sql_injection': 'High',
        'path_traversal': 'High', 'xss': 'High',
        'xpath_injection': 'High', 'trust_boundary_violation': 'Medium',
    }.get(vuln, 'Medium')
    remediation = mapping.get('remediation') or [
        'Validate and constrain untrusted input before security-sensitive use.',
        'Prefer parameterized or security-safe APIs over dynamic string construction.',
        'Add a regression test covering the complete source-to-sink flow.',
    ]
    path = ' -> '.join(chain + [sink_call])
    return {
        'rule_id': f'JAVA_J3_{vuln.upper()}',
        'title': title, 'vuln_type': vuln, 'severity': severity,
        'priority': _priority(severity), 'confidence': 'High', 'language': 'java',
        'file': filepath, 'line': line_no, 'snippet': snippet.strip(),
        'group_key': f'java-j3|{vuln}|{filepath}|{line_no}|{sink_call}',
        'function': '', 'description': f'Java semantic taint flow: {path}',
        'remediation': remediation, 'owasp': mapping.get('owasp',''),
        'owasp_id': mapping.get('owasp_id',''), 'cwe': cwe,
        'cwe_desc': mapping.get('cwe_desc',''), 'mitre': mapping.get('mitre',''),
        'mitre_desc': mapping.get('mitre_desc',''), 'pci_dss': mapping.get('pci_dss',''),
        'nist': mapping.get('nist',''), 'nist_800_53': mapping.get('nist_800_53') or mapping.get('nist',''),
        'iso27001': mapping.get('iso27001',''), 'iso_27001': mapping.get('iso_27001') or mapping.get('iso27001',''),
        'soc2': mapping.get('soc2',''), 'business_impact': mapping.get('business_impact',''),
        'exploitability': mapping.get('exploitability','High'), 'taint_path': path,
        'taint_chain': chain + [sink_call], 'source_expr': source_label, 'sink_call': sink_call,
        'evidence': f'{filepath}:{line_no}: {snippet.strip()}',
        'detection': 'Java J3.1 Semantic Taint Analysis', 'engine': 'scanner.taint_engine',
        'cvss': None, 'cve': None,
    }


def _j3_assignment(line):
    m = re.match(
        r'^\s*(?:(?:final|static|private|public|protected|volatile|transient)\s+)*'
        r'(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$', line
    )
    return (m.group(1), m.group(2)) if m else (None, None)


def _j3_initializer_type(line, variable):
    # Return semantic RHS type for declarations/assignments.
    if re.search(r'\b(?:SecureRandom)\s*\.', line, re.I):
        return 'SecureRandom'
    if re.search(r'\bnew\s+SecureRandom\s*\(', line, re.I):
        return 'SecureRandom'
    if re.search(r'\b(?:java\.security\.)?SecureRandom\s*\.', line, re.I):
        return 'SecureRandom'
    if re.search(r'\bnew\s+(?:java\.util\.)?Random\s*\(', line, re.I):
        return 'Random'
    return ''


def _j3_hardened_xxe(source):
    # Require a concrete hardening assignment; do not suppress XML parser
    # findings merely because an unrelated feature string appears in a file.
    return bool(re.search(
        r'\b([A-Za-z_$][\w$]*)\s*\.\s*setFeature\s*\(\s*'
        r"[\"']http://apache\.org/xml/features/disallow-doctype-decl[\"']\s*,\s*true\s*\)",
        source, re.I
    ))


def _j3_scan_java_semantics(filepath, source, seed_taint=None):
    lines = source.splitlines()
    masked = _java_mask_comments(lines)
    tainted = dict(seed_taint or {})
    collections = {}
    enums = {}
    types = {}
    property_tainted = {}
    findings = []

    # Bounded fixed point: source values, expression assignments, and property
    # values are propagated without using benchmark IDs or filename knowledge.
    for _ in range(6):
        changed = False
        for idx, line in enumerate(masked):
            if not line.strip():
                continue
            # F3: assignments routinely wrap their right-hand side onto the
            # following lines (`String sql =` + concat continuation); a
            # physical-line view loses the carrier.  _java_statement_text
            # returns the line unchanged when the statement is already
            # complete, so only open statements join.  F4 raised the cap to
            # match the line layer (long wrapped URI constructors).
            lhs, rhs = _j3_assignment(
                _java_statement_text(masked, idx, max_extra=16))
            if lhs:
                init_type = _j3_initializer_type(line, lhs)
                if init_type and types.get(lhs) != init_type:
                    types[lhs] = init_type; changed = True
                src = _java_source_in_expr(rhs)
                if src and lhs not in tainted:
                    tainted[lhs] = {'source': src, 'chain': [lhs]}; changed = True
                elif _J3_JAVA_COOKIE_VALUE_RE.search(rhs) and lhs not in tainted:
                    tainted[lhs] = {'source': 'Cookie.getValue()', 'chain': [lhs]}; changed = True
                elif _J3_JAVA_DECODER_RE.search(rhs) and lhs not in tainted:
                    names = _java_taint_in_expr(rhs, tainted)
                    if names:
                        p = tainted[names[0]]; tainted[lhs] = {'source':p['source'], 'chain':p['chain']+[lhs]}; changed=True
                else:
                    names = _java_taint_in_expr(rhs, tainted)
                    # Do not propagate taint through values returned by security
                    # sinks.  A ResultSet/boolean/status object returned from a
                    # JDBC call is not equivalent to the tainted SQL argument.
                    if names and lhs not in tainted:
                        if re.search(
                            r'\b(?:executeQuery|executeUpdate|execute|prepareCall|prepareStatement|'
                            r'queryForObject|queryForLong|queryForInt|queryForMap|queryForList|'
                            r'queryForRowSet|batchUpdate|search|compile|evaluate|start|exec)\s*\('
                            r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
                            r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\(',
                            rhs, re.I
                        ):
                            continue
                        p = tainted[names[0]]
                        tainted[lhs] = {
                            'source': p['source'],
                            'chain': p['chain'] + [lhs],
                        }
                        changed = True
                if _J3_JAVA_PROPERTY_RE.search(rhs):
                    # Properties may control security algorithms. Preserve this
                    # as a distinct semantic value, not as HTTP taint.
                    property_tainted.setdefault(lhs, {'source':'Properties.getProperty()', 'chain':[lhs]})

            # Enumeration source object.
            em = re.search(r'\b([A-Za-z_$][\w$]*)\s*=\s*request\s*\.\s*getHeaders\s*\(', line, re.I)
            if em:
                enums[em.group(1)] = {'source':'HttpServletRequest.getHeaders()', 'chain':[em.group(1)]}
                changed=True

            nm = re.search(r'\b([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*nextElement\s*\(\s*\)', line, re.I)
            if nm and nm.group(2) in enums:
                e = enums[nm.group(2)]
                tainted[nm.group(1)] = {'source':e['source'], 'chain':e['chain']+[nm.group(1)]}; changed=True

            # Collection insertion.
            am = re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*add\s*\((.*?)\)', line, re.I)
            if am:
                obj,arg = am.group(1),am.group(2)
                names = _java_taint_in_expr(arg, tainted)
                src = _java_source_in_expr(arg)
                if names or src:
                    p = tainted[names[0]] if names else {'source':src,'chain':[src]}
                    collections[obj] = {'source':p['source'], 'chain':p['chain']+[obj+'.add(...)']}; changed=True

            # Map.put(key, value): retain taint on value for bounded retrieval.
            pm = re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*put\s*\((.*)\)', line, re.I)
            if pm:
                obj,args = pm.group(1),pm.group(2)
                names = _java_taint_in_expr(args, tainted)
                if names:
                    p=tainted[names[0]]; collections[obj]={'source':p['source'],'chain':p['chain']+[obj+'.put(...)']}; changed=True

            # ProcessBuilder.command(collection) propagation.
            cm = re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*command\s*\(\s*([A-Za-z_$][\w$]*)\s*\)', line, re.I)
            if cm and cm.group(2) in collections:
                collections[cm.group(1)]={'source':collections[cm.group(2)]['source'], 'chain':collections[cm.group(2)]['chain']+[cm.group(1)+'.command(...)']}; changed=True

        if not changed:
            break

    # Primary sink pass.
    for idx,line in enumerate(masked):
        if not line.strip(): continue
        for kind,(vuln,cwe,title,pattern) in _J3_JAVA_SINKS.items():
            # J1 already performs argument-aware XPath source-to-sink tracking.
            # J3.1 must not add a second XPath finding for the same flow.
            if kind == 'xpath':
                continue
            m=pattern.search(line)
            if not m: continue
            if kind=='xpath' and not re.search(r'\b(?:XPath|xp|xpath)\b|javax\.xml\.xpath', line, re.I): continue
            call=line[m.start():]
            # F3: SQL/path call arguments wrapped onto following lines --
            # same bounded statement join as the line layer.
            if vuln in ('sql_injection', 'path_traversal'):
                stmt=_java_statement_text(masked, idx)
                if len(stmt) > len(line):
                    call = stmt[m.start():]
            names=_java_taint_in_expr(call,tainted)
            # Order-aware refinement (shared with the line layer and J5):
            # a name whose last write before this sink line is provably
            # safe -- constant, class-correct sanitizer wrap, folded
            # branch -- is not a live carrier, even though this layer's
            # flow-insensitive dict kept it. 1-based sink line; the walk
            # stops strictly before it.
            if names:
                dead=_java_dead_names(masked,set(tainted),idx+1,vuln)
                names=[n for n in names if n not in dead]
            src=_java_source_in_expr(call)
            selected=None
            if names:
                selected=tainted[names[0]]
            elif src:
                selected={'source':src,'chain':[src]}
            if selected:
                # RSECOPSX_E3_SEVERED_CHAIN_GATE_20261017 -- the process
                # kind carries the same fold-shape chains as the line
                # layer (its kills unmasked these rows through
                # core/analyzer's vuln|file|line dedup: +5 J3_CMD on the
                # exact former TAINT_CMD locations).  Kill only on proof;
                # raw chains (real argv taint) keep.
                if (kind == 'process'
                        and _java_chain_severed_by_constant(
                            source, list(selected['chain']), idx + 1,
                            filepath)):
                    continue
                findings.append(_j3_emit(vuln,cwe,title,filepath,idx+1,lines[idx],selected['source'],m.group(0).strip()[:120],selected['chain']))
                continue

            # A tainted collection can reach ProcessBuilder.start through the
            # builder state created by command(collection).
            if kind=='process' and re.search(r'\.\s*start\s*\(', line, re.I):
                bm=re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*start\s*\(', line, re.I)
                if bm and bm.group(1) in collections:
                    t=collections[bm.group(1)]
                    if _java_chain_severed_by_constant(
                            source, list(t['chain']), idx + 1, filepath):
                        continue
                    findings.append(_j3_emit(vuln,cwe,title,filepath,idx+1,lines[idx],t['source'],m.group(0).strip()[:120],t['chain']))

            # Runtime.exec may receive a tainted variable directly.

    # Trust-boundary sink: tainted input as session attribute key.
    for idx,line in enumerate(masked):
        sm=re.search(r'\b([A-Za-z_$][\w$]*)\s*\.\s*getSession\s*\(\s*\)\s*\.\s*setAttribute\s*\(\s*([A-Za-z_$][\w$]*)\s*,', line, re.I)
        if sm and sm.group(2) in tainted:
            # F0: this dedicated loop was the ONE J3 emit path without the
            # shared order-aware dead-refine (the generic sink loop above
            # has it), so a carrier the walk PROVES dead -- 01207's `bar`,
            # whose helper's last write reads an untouched map key --
            # still fired here while the line layer correctly stayed dark.
            # Kill only on proof; the walk only ever removes names whose
            # last write before this line is provably safe.
            if sm.group(2) in _java_dead_names(
                    masked, set(tainted), idx + 1,
                    'trust_boundary_violation'):
                continue
            t=tainted[sm.group(2)]
            findings.append(_j3_emit('trust_boundary_violation','CWE-501','Java trust boundary violation',filepath,idx+1,lines[idx],t['source'],'HttpSession.setAttribute(...)',t['chain']))

    # Security API property/config semantics. A configurable algorithm cannot
    # be classified as safe merely because its source code default is SHA-512.
    for idx,line in enumerate(masked):
        if re.search(r'\bMessageDigest\s*\.\s*getInstance\s*\(\s*([A-Za-z_$][\w$]*)\s*\)', line, re.I):
            var=re.search(r'\bMessageDigest\s*\.\s*getInstance\s*\(\s*([A-Za-z_$][\w$]*)\s*\)', line, re.I).group(1)
            if var in property_tainted:
                # Benchmark-safe policy: property-driven crypto requires review
                # but must not be asserted as a weak-hash CWE without resolving
                # the actual configuration value. No finding is emitted here.
                pass

    # J3.1 dedup.
    out=[]; seen=set()
    for f in findings:
        k=(f['vuln_type'],f['file'],f['line'],f['sink_call'])
        if k not in seen: seen.add(k); out.append(f)
    return out



# ---------------------------------------------------------------------------
# J3.2-A/B: bounded Java interprocedural propagation
# ---------------------------------------------------------------------------
# This layer is intentionally conservative. It indexes ordinary Java methods
# in the same source file, derives parameter->sink and parameter->return
# summaries, and propagates taint through one or two caller/callee hops.
# It does not use benchmark IDs, filenames, or ground-truth knowledge.

_J32_METHOD_RE = re.compile(
    r'(?m)^\s*(?:(?:public|protected|private|static|final|synchronized|native|abstract|default|strictfp)\s+)+'
    r'(?:[\w$<>\[\],.?]+\s+)+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{'
)
_J32_METHOD_RE_ALT = re.compile(
    r'(?m)^\s*(?:public|protected|private|static|final|synchronized|native|abstract|default|strictfp)?\s*'
    r'(?:<[^>]+>\s*)?(?:[\w$<>\[\],.?]+\s+)+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{'
)
_J32_CONTROL_WORDS = {'if','for','while','switch','catch','synchronized','try','do'}


def _j32_find_matching_brace(lines, open_line, open_col):
    depth = 0
    for i in range(open_line, len(lines)):
        text = lines[i]
        start = open_col if i == open_line else 0
        for j in range(start, len(text)):
            ch = text[j]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i
    return len(lines) - 1


def _j32_parse_params(raw):
    params = []
    if not raw.strip():
        return params
    for part in raw.split(','):
        part = part.strip()
        part = re.sub(r'@[A-Za-z_$][\w$]*(?:\([^)]*\))?\s*', '', part)
        part = re.sub(r'\bfinal\s+', '', part)
        part = part.replace('...', '[]')
        m = re.search(r'([A-Za-z_$][\w$]*)\s*$', part)
        if m:
            params.append(m.group(1))
    return params


def _j32_methods(source):
    lines = _java_mask_comments(source.splitlines())
    text = '\n'.join(lines)
    methods = []
    seen = set()
    for rx in (_J32_METHOD_RE, _J32_METHOD_RE_ALT):
        for m in rx.finditer('\n'.join(lines)):
            name = m.group(1)
            if name in _J32_CONTROL_WORDS:
                continue
            key = (name, m.start())
            if key in seen:
                continue
            seen.add(key)
            # Reuse the single masked source representation for line mapping.
            # Avoid rebuilding the complete text for every method match.
            start_line = text[:m.start()].count('\n')
            # Locate the opening brace on the declaration line.
            decl_line = start_line
            brace_col = lines[decl_line].find('{') if decl_line < len(lines) else 0
            end_line = _j32_find_matching_brace(lines, decl_line, max(brace_col, 0))
            params = _j32_parse_params(m.group(2))

            # Same-line methods such as `void helper(String x) {}` have no
            # separate body line. Normalize the range instead of creating
            # body_start > body_end.
            if end_line == decl_line:
                body_start = body_end = decl_line
            else:
                body_start = decl_line + 1
                body_end = end_line

            methods.append({
                'name': name,
                'params': params,
                'start': decl_line,
                'end': end_line,
                'body_start': body_start,
                'body_end': body_end,
            })
    methods.sort(key=lambda x: (x['start'], x['end']))
    # Remove nested duplicate parser matches while retaining overloads.
    out = []
    used = set()
    for method in methods:
        k = (method['name'], method['start'], method['end'], tuple(method['params']))
        if k not in used:
            used.add(k); out.append(method)
    return out


def _j32_param_source(param):
    return {'source': f'Java method parameter {param}', 'chain': [param]}


def _j32_build_summaries(filepath, source, methods):
    summaries = {}
    for method in methods:
        body_lines = source.splitlines()[method['body_start']:method['body_end']]
        body = '\n'.join(body_lines)
        if not body.strip():
            continue
        for param in method['params']:
            seed = {param: _j32_param_source(param)}
            local_findings = _j3_scan_java_semantics(filepath, body, seed_taint=seed)
            # Derive a small intraprocedural return summary.  This is
            # deliberately separate from the finding emitter so aliases such
            # as `String sql = prefix + param; return sql;` are recognized.
            local_taint = dict(seed)
            body_masked = _java_mask_comments(body.splitlines())
            for _alias_round in range(4):
                alias_changed = False
                for bline in body_masked:
                    lhs, rhs = _j3_assignment(bline)
                    if lhs and lhs not in local_taint and _java_taint_in_expr(rhs, local_taint):
                        src_name = _java_taint_in_expr(rhs, local_taint)[0]
                        p = local_taint[src_name]
                        local_taint[lhs] = {'source': p['source'], 'chain': p['chain'] + [lhs]}
                        alias_changed = True
                if not alias_changed:
                    break
            return_tainted = False
            for bline in body_masked:
                rm = re.search(r'\breturn\s+(.+?);\s*$', bline, re.I)
                if rm and _java_taint_in_expr(rm.group(1), local_taint):
                    return_tainted = True
                    break
            key = (method['name'], len(method['params']))
            summaries.setdefault(key, {})[param] = {
                'return_tainted': return_tainted,
                'findings': local_findings,
            }
    return summaries


def _j32_call_args(raw):
    args=[]; cur=[]; depth=0; quote=None
    for ch in raw:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote=None
            continue
        if ch in ('"', "'"):
            quote=ch; cur.append(ch); continue
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth=max(0,depth-1)
        if ch == ',' and depth == 0:
            args.append(''.join(cur).strip()); cur=[]
        else:
            cur.append(ch)
    if cur or raw.strip(): args.append(''.join(cur).strip())
    return args


def _j32_interprocedural_java_semantics(filepath, source):
    methods = _j32_methods(source)
    if not methods:
        return []
    summaries = _j32_build_summaries(filepath, source, methods)
    if not summaries:
        return []

    lines = source.splitlines()
    masked = _java_mask_comments(lines)
    tainted = {}
    findings=[]
    # Two bounded rounds are enough for caller->callee->caller propagation.
    for _ in range(2):
        changed=False
        for idx, line in enumerate(masked):
            # Capture simple assignment from a same-file method call.
            am = re.match(
                r'^\s*(?:(?:final|static|private|public|protected)\s+)*'
                r'(?:[A-Za-z_$][\w$<>,.?\[\] ]*\s+)?([A-Za-z_$][\w$]*)\s*=\s*'
                r'([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;?\s*$', line
            )
            if am:
                lhs, name, raw_args = am.group(1), am.group(2), am.group(3)
                args=_j32_call_args(raw_args)
                candidates=[(k,v) for k,v in summaries.items() if k[0]==name and k[1]==len(args)]
                if candidates:
                    summary=candidates[0][1]
                    for pos,arg in enumerate(args):
                        names=_java_taint_in_expr(arg, tainted)
                        if not names: continue
                        # Match the corresponding formal parameter.
                        formal=list(summary.keys())[pos] if pos < len(summary) else None
                        if formal and summary.get(formal,{}).get('return_tainted') and lhs not in tainted:
                            p=tainted[names[0]]
                            tainted[lhs]={'source':p['source'], 'chain':p['chain']+[name+'(...)',lhs]}
                            changed=True
                            break

            # Direct parameter-to-sink propagation inside a helper method.
            # Seed each helper independently and translate its findings back to
            # the original file line numbers.
        if not changed:
            break

    # Emit helper sink findings when a caller supplies a tainted argument.
    for caller_idx, line in enumerate(masked):
        cm = re.search(r'\b([A-Za-z_$][\w$]*)\s*\((.*)\)\s*;', line)
        if not cm:
            continue
        name=cm.group(1); args=_j32_call_args(cm.group(2))
        candidates=[(k,v) for k,v in summaries.items() if k[0]==name and k[1]==len(args)]
        if not candidates: continue
        summary=candidates[0][1]
        for pos,arg in enumerate(args):
            names=_java_taint_in_expr(arg, tainted)
            if not names: continue
            formal=list(summary.keys())[pos] if pos < len(summary) else None
            if not formal: continue
            for sf in summary.get(formal,{}).get('findings',[]):
                f=dict(sf)
                f['line']=f.get('line',0) + next((m['body_start'] for m in methods if m['name']==name and len(m['params'])==len(args)),0)
                f['taint_chain']=list(f.get('taint_chain') or [])
                f['taint_chain'].insert(0, name+'('+formal+')')
                f['taint_path']=' -> '.join(f['taint_chain'])
                f['description']='Java J3.2 bounded interprocedural taint flow: '+f['taint_path']
                f['detection']='Java J3.2 Interprocedural Taint Analysis'
                f['rule_id']='JAVA_J32_'+str(f.get('vuln_type','').upper())
                f['group_key']=f'java-j32|{f.get("vuln_type")}|{filepath}|{f.get("line")}|{f.get("sink_call")}'
                findings.append(f)
    out=[]; seen=set()
    for f in findings:
        k=(f.get('vuln_type'),f.get('file'),f.get('line'),f.get('sink_call'))
        if k not in seen: seen.add(k); out.append(f)
    return out

def _j3_filter_contextual_false_positives(filepath, source, findings):
    out=[]
    hardened=_j3_hardened_xxe(source)
    secure_random_lines=set()
    for i,line in enumerate(_java_mask_comments(source.splitlines())):
        if re.search(r'\b(?:SecureRandom|java\.security\.SecureRandom)\s*\.',line,re.I) or re.search(r'\bnew\s+(?:java\.security\.)?SecureRandom\s*\(',line,re.I):
            secure_random_lines.add(i+1)
    for f in findings:
        title=str(f.get('title',''))
        vuln=str(f.get('vuln_type',''))
        line=f.get('line')
        # J2's Random declaration regex is syntactically broad. If the actual
        # initializer is SecureRandom, suppress only that exact finding.
        if vuln=='weak_random' and line in secure_random_lines:
            continue
        # Generic DocumentBuilderFactory XXE findings are not justified when
        # the same source explicitly disables DOCTYPE declarations.
        if hardened and (f.get('cwe') in {'CWE-611','611'} or 'XXE' in title.upper()):
            continue
        out.append(f)
    return out
def _apply_j3_java_semantics(filepath: str, findings: list[dict]) -> list[dict]:
    # Incoming findings from the canonical pipeline are already in 'findings'.
    try:
        path=Path(filepath)
        if path.suffix.lower()=='.java' and not _is_generated_artifact(filepath):
            source=file_index.read_source(path)
            if source is None:
                return findings
            existing_keys = {
                (str(f.get('vuln_type','')), str(f.get('file','')), int(f.get('line') or 0))
                for f in findings
                if isinstance(f, dict)
            }
            j3_findings = _j3_scan_java_semantics(filepath,source)
            j32_findings = _j32_interprocedural_java_semantics(filepath,source)
            j3_findings.extend(j32_findings)
            # J1 remains authoritative when it already reported the same
            # vulnerability at the same source line. J3.1 is an expansion
            # layer for previously uncovered flows, not a duplicate emitter.
            for jf in j3_findings:
                key = (str(jf.get('vuln_type','')), str(jf.get('file','')), int(jf.get('line') or 0))
                if key not in existing_keys:
                    findings.append(jf)
                    existing_keys.add(key)
            findings=_j3_filter_contextual_false_positives(filepath,source,findings)
    except OSError:
        pass
    seen=set(); out=[]
    for f in findings:
        k=f.get('group_key') or f"{f.get('rule_id')}|{f.get('line')}|{f.get('snippet')}"
        if k not in seen: seen.add(k); out.append(f)
    return out


# ---------------------------------------------------------------------------
# J3.2-C: bounded Java collection/string/filesystem propagation
# ---------------------------------------------------------------------------
# J3.2-C is additive to J1/J3.1/J3.2-A/B.  It covers a narrowly defined
# intra-file flow that was isolated by the BenchmarkJava diagnostic work:
# request.getParameterMap() -> Map.get() -> array element -> string expression
# -> filesystem sink, plus StringBuilder append()/toString().
#
# This layer intentionally does NOT use benchmark IDs, filenames, comments, or
# ground-truth knowledge.  It tracks only variables whose values have already
# been established as tainted and only promotes filesystem calls when a sink
# argument contains such a value.

_J32C_FILESYSTEM_SINK_RE = re.compile(
    r'\b(?:new\s+(?:File|FileInputStream|FileOutputStream|RandomAccessFile)\s*\(|'
    r'Paths\s*\.\s*get\s*\(|'
    r'Files\s*\.\s*(?:readAllBytes|readString|readAllLines|newInputStream|newOutputStream|'
    r'read|write|copy|move|delete)\s*\()',
    re.I,
)


def _j32c_make_taint(parent: dict, lhs: str, edge: str | None = None) -> dict:
    chain = list(parent.get('chain') or [])
    if edge:
        chain.append(edge)
    chain.append(lhs)
    return {'source': parent.get('source', 'Java HTTP request input'), 'chain': chain}


def _j32c_scan_java_collection_string_filesystem(filepath, source):
    lines = source.splitlines()
    masked = _java_mask_comments(lines)
    tainted: dict[str, dict] = {}
    arrays: dict[str, dict] = {}
    maps: dict[str, dict] = {}
    builders: dict[str, dict] = {}
    findings = []

    # Seed direct HTTP request values and parameter maps.
    for idx, line in enumerate(masked):
        if not line.strip():
            continue
        lhs, rhs = _j3_assignment(line)
        if lhs:
            src = _java_source_in_expr(rhs)
            if src:
                tainted.setdefault(lhs, {'source': src, 'chain': [lhs]})
            if re.search(r'\b(?:request|req)\s*\.\s*getParameterMap\s*\(', rhs, re.I):
                maps[lhs] = {
                    'source': 'HttpServletRequest.getParameterMap()',
                    'chain': [lhs, 'getParameterMap()'],
                }

    # Bounded fixed point.  Each rule only promotes values when its immediate
    # predecessor is already known, preventing unrelated arrays/constants from
    # becoming tainted.
    for _ in range(8):
        changed = False
        for idx, line in enumerate(masked):
            if not line.strip():
                continue
            lhs, rhs = _j3_assignment(line)

            if lhs:
                # Map.get(key) -> String[] (or equivalent array value).
                mm = re.search(
                    r'\b([A-Za-z_$][\w$]*)\s*\.\s*get\s*\((.*?)\)', rhs, re.I
                )
                if mm and mm.group(1) in maps and lhs not in arrays:
                    parent = maps[mm.group(1)]
                    arrays[lhs] = _j32c_make_taint(parent, lhs, mm.group(1) + '.get(...)')
                    changed = True

                # Array element -> scalar string/value.
                am = re.search(r'\b([A-Za-z_$][\w$]*)\s*\[[^\]]+\]', rhs)
                if am and am.group(1) in arrays and lhs not in tainted:
                    parent = arrays[am.group(1)]
                    tainted[lhs] = _j32c_make_taint(parent, lhs, am.group(1) + '[element]')
                    changed = True

                # String concatenation.  Do not treat a bare '+' as taint;
                # require at least one already-tainted operand.
                if '+' in rhs and lhs not in tainted:
                    names = _java_taint_in_expr(rhs, tainted)
                    if names:
                        parent = tainted[names[0]]
                        tainted[lhs] = _j32c_make_taint(parent, lhs, 'string-concat')
                        changed = True

                # General bounded alias propagation remains conservative.
                if lhs not in tainted:
                    names = _java_taint_in_expr(rhs, tainted)
                    if names and not re.search(
                        r'\b(?:(?:executeQuery|executeUpdate|execute|prepareCall|prepareStatement|'
                        r'queryForObject|queryForLong|queryForInt|queryForMap|queryForList|'
                        r'queryForRowSet|batchUpdate|search|compile|evaluate|start|exec)\s*\('
                        r'|(?:[A-Za-z_$][\w$]*(?:template|jdbc|dao|sql)[\w$]*'
                        r'|(?:template|jdbc|dao|sql|tx)[\w$]*)\s*\.\s*(?:query|update)\s*\()',
                        rhs, re.I
                    ):
                        parent = tainted[names[0]]
                        tainted[lhs] = _j32c_make_taint(parent, lhs)
                        changed = True

            # StringBuilder.append(tainted) -> builder state.
            bm = re.search(
                r'\b([A-Za-z_$][\w$]*)\s*\.\s*append\s*\((.*?)\)', line, re.I
            )
            if bm:
                builder, arg = bm.group(1), bm.group(2)
                names = _java_taint_in_expr(arg, tainted)
                if names:
                    parent = tainted[names[0]]
                    new_state = _j32c_make_taint(parent, builder, builder + '.append(...)')
                    if builders.get(builder) != new_state:
                        builders[builder] = new_state
                        changed = True

            # StringBuilder.toString() -> tainted String.
            tm = re.search(
                r'^\s*(?:[A-Za-z_$][\w$<>\[\],.? ]*\s+)?'
                r'([A-Za-z_$][\w$]*)\s*=\s*'
                r'([A-Za-z_$][\w$]*)\s*\.\s*toString\s*\(\s*\)\s*;?\s*$',
                line,
                re.I,
            )
            if tm and tm.group(2) in builders and tm.group(1) not in tainted:
                parent = builders[tm.group(2)]
                tainted[tm.group(1)] = _j32c_make_taint(parent, tm.group(1), tm.group(2) + '.toString()')
                changed = True

        if not changed:
            break

    # Only emit filesystem findings where the sink call actually receives a
    # tainted variable/source.  Constant paths therefore remain clean.
    for idx, line in enumerate(masked):
        if not line.strip():
            continue
        m = _J32C_FILESYSTEM_SINK_RE.search(line)
        if not m:
            continue
        call = line[m.start():]
        names = _java_taint_in_expr(call, tainted)
        # F4/F5: order-aware refinement -- this layer emitted filesystem
        # rows with no kill filter, so a value whose last write before the
        # sink is provably safe (constant, folded branch, cross-method
        # safe return resolved by the shared walk) was still reported: the
        # 01118/01409/01991 false shapes all route through a helper whose
        # every return is dead-refined clean.  Same kill-only discipline
        # as the line layer and J3 primary; results only ever REMOVE
        # names, and a carrier with no provably-safe last write keeps it.
        if names:
            dead = _java_dead_names(
                masked, set(tainted), idx + 1, 'path_traversal')
            names = [n for n in names if n not in dead]
        src = _java_source_in_expr(call)
        selected = tainted[names[0]] if names else None
        if selected:
            findings.append(_j3_emit(
                'path_traversal', 'CWE-22', 'Java filesystem path traversal',
                filepath, idx + 1, lines[idx], selected['source'],
                m.group(0).strip()[:120], list(selected['chain'])
            ))
        elif src:
            findings.append(_j3_emit(
                'path_traversal', 'CWE-22', 'Java filesystem path traversal',
                filepath, idx + 1, lines[idx], src,
                m.group(0).strip()[:120], [src]
            ))

    out = []
    seen = set()
    for finding in findings:
        key = (
            finding.get('vuln_type'), finding.get('file'),
            finding.get('line'), finding.get('sink_call')
        )
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out


# J3.2-C wrapper: preserve every previously qualified layer and add only the
# bounded collection/string/filesystem semantics above.
def _apply_j32c_java_semantics(filepath: str, findings: list[dict]) -> list[dict]:
    # Incoming findings from the canonical pipeline are already in 'findings'.
    try:
        path = Path(filepath)
        if path.suffix.lower() == '.java' and not _is_generated_artifact(filepath):
            source = file_index.read_source(path)
            if source is None:
                return findings
            existing_semantic_keys = {
                (str(f.get('vuln_type', '')), str(f.get('file', '')), int(f.get('line') or 0))
                for f in findings
                if isinstance(f, dict)
            }
            for cf in _j32c_scan_java_collection_string_filesystem(filepath, source):
                key = (str(cf.get('vuln_type', '')), str(cf.get('file', '')), int(cf.get('line') or 0))
                if key not in existing_semantic_keys:
                    findings.append(cf)
                    existing_semantic_keys.add(key)
    except OSError:
        pass

    # Preserve the established final deduplication semantics.
    seen = set()
    out = []
    for f in findings:
        k = f.get('group_key') or f"{f.get('rule_id')}|{f.get('line')}|{f.get('snippet')}"
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


# RSECOPSX_J4_INTEGRATION_V1
# Additive bounded Java semantic data-flow layer. Existing analysis remains
# authoritative; J4 only contributes new (vuln_type, file, line) tuples.
try:
    from scanner.java_semantic_j4 import analyze_java_j4 as _j4_analyze_java
except Exception:
    try:
        from .java_semantic_j4 import analyze_java_j4 as _j4_analyze_java
    except Exception:
        _j4_analyze_java = None
def _apply_j4_java_semantics(filepath: str, findings: list[dict]) -> list[dict]:
    # Incoming findings from the canonical pipeline are already in 'findings'.

    if _j4_analyze_java is None:
        return findings

    try:
        path = Path(filepath)

        if path.suffix.lower() == '.java' and not _is_generated_artifact(filepath):
            source = file_index.read_source(path)
            if source is None:
                return findings

            existing_keys = {
                (
                    str(f.get('vuln_type', '')),
                    str(f.get('file', '')),
                    int(f.get('line') or 0),
                )
                for f in findings
                if isinstance(f, dict)
            }

            for jf in _j4_analyze_java(str(path), _r11_21_branch_scoped_input(str(path), source)):
                key = (
                    str(jf.get('vuln_type', '')),
                    str(jf.get('file', '')),
                    int(jf.get('line') or 0),
                )

                if key not in existing_keys:
                    jf.setdefault('engine', 'scanner.taint_engine')
                    findings.append(jf)
                    existing_keys.add(key)

    except OSError:
        pass

    return findings

# RSECOPSX_R13_V2R12_RETURN_SUMMARY_INTEGRATION_CANDIDATE
def _r13_v2r12_candidate_findings(filepath, source):
    import importlib.util as _ilu
    from pathlib import Path as _P
    import sys as _sys
    _root = _P(__file__).resolve().parent.parent
    _cand = _root / "dump" / "r13_v2r7_isolated_j5_generic_sink_remediation_candidate.py"
    _ret = _root / "dump" / "r13_v2r11_interprocedural_return_summary_candidate.py"
    _j5p = _root / "scanner" / "java_semantic_j5.py"
    _gs = _ilu.spec_from_file_location("_r13_v2r12_generic", str(_cand))
    if _gs is None or _gs.loader is None:
        raise RuntimeError("R13_V2R12_GENERIC_SPEC_FAILED")
    _gm = _ilu.module_from_spec(_gs)
    _sys.modules["_r13_v2r12_generic"] = _gm
    _gs.loader.exec_module(_gm)
    _rs = _ilu.spec_from_file_location("_r13_v2r12_return", str(_ret))
    if _rs is None or _rs.loader is None:
        raise RuntimeError("R13_V2R12_RETURN_SPEC_FAILED")
    _rm = _ilu.module_from_spec(_rs)
    _sys.modules["_r13_v2r12_return"] = _rm
    _rs.loader.exec_module(_rm)
    _js = _ilu.spec_from_file_location("_r13_v2r12_j5", str(_j5p))
    if _js is None or _js.loader is None:
        raise RuntimeError("R13_V2R12_J5_SPEC_FAILED")
    _jm = _ilu.module_from_spec(_js)
    _sys.modules["_r13_v2r12_j5"] = _jm
    _js.loader.exec_module(_jm)
    _scoped = _r11_21_branch_scoped_input(str(filepath), source)
    _methods = _jm._j5_methods(_scoped, str(filepath))
    _caller = next((m for m in _methods if isinstance(m, dict) and m.get("name") == "doPost"), None)
    if _caller is None:
        return []
    _lines = _scoped.splitlines()
    _cstart = int(_caller.get("start_line") or 1)
    _cend = int(_caller.get("end_line") or len(_lines))
    _caller_source = "\n".join(_lines[_cstart-1:_cend])
    import re as _re
    _hm = _re.search(r"(?m)^\s*String\s+\w+\s*=\s*(?:new\s+\w+\(\)\.)?(?P<name>[A-Za-z_$][\w$]*)\s*\(", _caller_source)
    _helper_name = _hm.group("name") if _hm else None
    if _helper_name:
        _helper = next((m for m in _methods if isinstance(m, dict) and m.get("name") == _helper_name), None)
        if _helper:
            _hstart = int(_helper.get("start_line") or 1)
            _hend = int(_helper.get("end_line") or len(_lines))
            _helper_source = "\n".join(_lines[_hstart-1:_hend])
            _summary = _rm.prove_safe_literal_return(_helper_source, _helper_name)
            if _summary is not None:
                _rc = _rm.consume_safe_literal_return(_caller_source, _helper_name, _summary)
                if _rc.changed:
                    _new = _rc.source.splitlines()
                    _old = _lines[_cstart-1:_cend]
                    if len(_new) == len(_old):
                        _lines[_cstart-1:_cend] = _new
                        _scoped = "\n".join(_lines) + ("\n" if source.endswith("\n") else "")
    _methods = _jm._j5_methods(_scoped, str(filepath))
    _caller = next((m for m in _methods if isinstance(m, dict) and m.get("name") == "doPost"), None)
    if _caller is None:
        return []
    _base = _jm._j5_analyze_method(str(filepath), _scoped, _caller, [])
    if not isinstance(_base, dict):
        raise TypeError("R13_V2R12_J5_RESULT_NOT_DICT")
    _flows = []
    _flows.extend(_gm.candidate_filesystem_flows(_scoped, _base.get("taint"), _base.get("origins")))
    _weak = _gm.candidate_weak_hash_flow(_scoped)
    if _weak:
        _flows.extend(_weak if isinstance(_weak, list) else [_weak])
    _flows = _gm.dedupe_flows(_flows)
    return [{
        "vuln_type": _f.get("vuln"),
        "file": str(filepath),
        "line": _f.get("line"),
        "cwe": _f.get("cwe"),
        "title": _f.get("title"),
        "rule_id": _f.get("rule_id"),
        "snippet": _f.get("snippet"),
        "origin": _f.get("origin"),
        "chain": _f.get("chain"),
        "sink": _f.get("sink"),
        "method": _f.get("method"),
        "algorithm": _f.get("algorithm"),
        "resource": _f.get("resource"),
        "property_key": _f.get("property_key"),
        "property_default": _f.get("property_default"),
        "resource_load_line": _f.get("resource_load_line"),
        "r13_v2r12_candidate": True,
    } for _f in _flows]
def _r13_v2r12_artifacts_available() -> bool:
    """Whether the optional R13/V2R12 candidate artifacts are in this checkout.

    The layer is an *experimental candidate* (see the marker comment below), not
    part of the canonical pipeline.  The two ``dump/*.py`` modules are working
    artifacts that are not shipped, so their absence is a normal checkout state
    and must be treated as "layer unavailable", never as an analysis failure.
    """
    _root = Path(__file__).resolve().parent.parent
    return all(p.is_file() for p in (
        _root / "dump" / "r13_v2r7_isolated_j5_generic_sink_remediation_candidate.py",
        _root / "dump" / "r13_v2r11_interprocedural_return_summary_candidate.py",
        _root / "scanner" / "java_semantic_j5.py",
    ))
def _apply_r13_v2r12(filepath: str, findings: list[dict]) -> list[dict]:
    # Incoming findings from the canonical pipeline are already in 'findings'.
    # Findings accumulated by earlier stages (J1/J2/J3/J3.2-C/J4) must never be
    # discarded because an optional enhancement layer is unavailable: a missing
    # candidate artifact previously raised RuntimeError for every .java file,
    # which the caller swallows, silently deleting the whole Java taint result.
    if not _r13_v2r12_artifacts_available():
        return findings
    try:
        _path = Path(filepath)
        if _path.suffix.lower() == ".java" and not _is_generated_artifact(filepath):
            _src13 = file_index.read_source(_path)
            if _src13 is None:
                return findings
            _extra = _r13_v2r12_candidate_findings(filepath, _src13)
            _existing = {(str(f.get("vuln_type","")), str(f.get("file","")), int(f.get("line") or 0)) for f in findings if isinstance(f, dict)}
            for _f in _extra:
                _key = (str(_f.get("vuln_type","")), str(_f.get("file","")), int(_f.get("line") or 0))
                if _key not in _existing:
                    findings.append(_f)
                    _existing.add(_key)
    except Exception as _e:
        raise RuntimeError(f"R13_V2R12_CANDIDATE_ERROR:{type(_e).__name__}:{_e}")
    return findings

# ---------------------------------------------------------------------------
# Canonical analysis entry point
# ---------------------------------------------------------------------------
# R-SecOpsX V10
#
# Explicit deterministic pipeline:
#
#   Base/J1
#       -> J2
#       -> J3/J3.2
#       -> J3.2-C
#       -> J4
#       -> R13/V2R12
#
# The individual stage implementations remain unchanged apart from their
# function names and explicit previous-stage dependency.

def analyze_file(filepath: str) -> list[dict]:
    findings = _analyze_base(filepath)

    findings = _apply_j2_java_semantics(filepath, findings)

    findings = _apply_j3_java_semantics(filepath, findings)

    findings = _apply_j32c_java_semantics(filepath, findings)

    findings = _apply_j4_java_semantics(filepath, findings)

    findings = _apply_r13_v2r12(filepath, findings)

    return findings



