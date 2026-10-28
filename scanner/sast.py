"""
scanner/sast.py
R-SecOpsX enterprise SAST regex layer.

Backward compatible public API:
- scan_file(filepath) -> list[dict]
- scan_directory(target_path, workers=2) -> list[dict]
- summarize_enterprise_controls(findings) -> dict

This file intentionally keeps high-risk pattern checks here and leaves source-to-sink
validation to scanner/taint_engine.py. Offline static analysis only.
"""
from __future__ import annotations

import logging
import re
import tokenize
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# Namespaced under the tool's own logger tree so these records reach both the
# console and the durable scan.log that main.py installs.  A bare
# "scanner.sast" would fall through to root and disappear unless --debug had
# configured it.
_LOG = logging.getLogger("rsx.scanner.sast")

try:
    from core.mapper import get_mapping
except Exception:  # fallback for standalone compile/use
    def get_mapping(vuln_type: str) -> dict:
        return {}

# T-0.1 (task.md ground rule 3): the shell-sink taint gate deletes findings;
# every deletion must carry a machine-readable reason.  filter_trace imports
# nothing from the project, so this cannot create a cycle.
from core import filter_trace
# T-0.5 (task.md ground rule 12): every rule-table finditer runs through
# the per-regex wall-clock budget; breaches emit REGEX_TIMEOUT telemetry.
from core import regex_budget
# T-0.2 (task.md): the canonical skip policy, language map and the one
# walk live in core.file_index; the historical names below are re-exported
# so every existing `from scanner.sast import _skip` keeps working.
from core import file_index
# T-0.6: the rule tables are declarative (rules/*_v1.yaml,
# schema-validated by core.rule_loader); the loader adapts them to the
# legacy shapes below. The PHP webshell pack stays code-side and is
# appended after load (its env switch removes it at registration).
from core.rule_loader import (load_disabled_ids as _load_disabled_ids,
                             load_enterprise_rules,
                             load_regex_rules,
                             load_sink_categories)

try:
    from core.deduplicator import group_findings
except Exception:
    def group_findings(findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        out: list[dict] = []
        for f in findings:
            k = f.get("group_key") or f"{f.get('rule_id')}|{f.get('file')}|{f.get('line')}|{f.get('snippet')}"
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out

_F = re.IGNORECASE | re.MULTILINE | re.DOTALL

# IANA HTTP method names (RFC 9110).  A comparison literal that is one of
# these can never be secret material, so HARDCODED_CREDENTIAL_COMPARISON's
# claim ("the secret is committed to source") is false by construction --
# django csrf.py:345 ``if token_source != "POST":`` fired only because the
# variable carried the ``token`` noun while the literal is a routing verb.
_HTTP_METHOD_VERBS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
)

SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".scala", ".go",
    ".rb", ".php", ".cs", ".vb", ".cpp", ".c", ".h", ".hpp", ".rs", ".sh",
    ".sol", ".erb",
    ".env", ".yml", ".yaml", ".properties", ".xml", ".json", ".graphql", ".gql",
    ".gradle", ".csproj", ".config", ".tf", ".Dockerfile", "Dockerfile",
}
EXCLUDED_FILES = file_index.EXCLUDED_FILES

# qbom.json added with the Quantum BOM artifact (CERT-In v2.0 Table 8). The handoff
# lists this exact hazard: a new artifact filename must be excluded or the scanner
# reads its own output back as scanned input. T-0.2: this is now the UNION of
# every scan-path engine's list -- see core/file_index.py for per-entry provenance.
EXCLUDED_DIRS = file_index.EXCLUDED_DIRS

LANG_BY_EXT = file_index.LANG_BY_EXT

BASE_REMEDIATION = {
    "xxe": ["Disable DTD and external entity resolution in XML parsers.", "Use safe parser factories with secure processing enabled.", "Reject untrusted XML or convert to JSON where possible."],
    "insecure_deserialization": ["Do not deserialize untrusted data.", "Use safe serializers and strict type allow-lists.", "Authenticate and integrity-protect serialized payloads."],
    "tls_bypass": ["Never disable certificate or hostname validation.", "Use platform trust stores and certificate pinning where appropriate.", "Fail closed on TLS validation errors."],
    "open_redirect": ["Validate redirect destinations against a server-side allow-list.", "Prefer relative redirects.", "Reject user-controlled absolute URLs."],
    "log_injection": ["Normalize CR/LF and control characters before logging.", "Use structured logging and encode untrusted fields.", "Avoid logging secrets or raw request payloads."],
    "zipslip": ["Canonicalize extracted paths and enforce destination directory containment.", "Reject entries containing .. or absolute paths.", "Use safe extraction helpers."],
    "redos": ["Rewrite catastrophic regex patterns using bounded quantifiers or safe regex engines.", "Avoid building RegExp from user input.", "Add input length limits and timeouts."],
    "mass_assignment": ["Bind request bodies to explicit DTOs, not persistence/domain entities.", "Use allow-listed fields and validation annotations.", "Reject privileged fields such as role, tenantId, isAdmin, status."],
    "client_controlled_amount": ["Never accept monetary values (price, amount, discount, order_total) from the client.", "Recompute totals server-side from catalog and cart state.", "Treat any client-supplied amount as a hint only and validate it server-side."],
    "dangerous_reflection": ["Avoid bypassing access checks through reflection.", "Do not call setAccessible(true) on user-influenced classes or members.", "Use explicit allow-lists for reflective operations."],
    "template_injection": ["Do not evaluate user-controlled templates.", "Use safe template contexts and escaping.", "Separate template names from template content."],
    "graphql_exposure": ["Disable GraphQL introspection in production unless explicitly required.", "Require authentication and authorization on GraphQL endpoints.", "Add query depth, complexity and rate limits."],
    "resource_exhaustion": ["Set explicit request/body/upload limits and operation timeouts at the server boundary.", "For GraphQL or expensive queries, enforce depth/complexity limits before execution.", "Stream large inputs where possible and rate-limit expensive operations; add tests for oversized and repeated requests."],
    "race_condition": ["Protect shared mutable state with locks/transactions.", "Use idempotency keys for duplicate actions.", "Make check-and-act operations atomic."],
    "api_rate_limit": ["Add server-side per-account/per-IP/per-tenant limits appropriate to the endpoint.", "Add progressive backoff for login/OTP/reset and idempotency keys for payment or other duplicate-sensitive actions.", "Return 429 on throttling, emit abuse metrics, and add burst/replay regression tests."],
    "buffer_overflow": ["Use bounded string functions (strncpy/snprintf) and always pass the destination size.", "Validate and length-limit untrusted input before copying into fixed buffers.", "Prefer fixed-size or dynamically-sized containers over raw char* buffers."],
    "format_string": ["Never pass untrusted or variable data as the printf format argument; use a literal format string.", "Use printf(\"%s\", value) so the value is an argument, not the format.", "Audit %n usage and disable it where the runtime allows."],
    "use_after_free": ["Set the pointer to NULL immediately after free() and check before reuse.", "Do not dereference a pointer after it has been freed; clear all aliases.", "Prefer RAII/smart pointers or an ownership discipline that prevents double-free/use-after-free."],
    "session_fixation": ["Regenerate/clear the session identifier before establishing an authenticated session.", "In Flask-Login, call session.clear() (or rotate the session id) before login_user().", "Reject pre-set session cookies at login and invalidate the anonymous session id."],
    "host_header_injection": ["Do not build absolute URLs or emails from the untrusted Host header.", "Use a configured, allow-listed base URL/host for outbound links and password-reset emails.", "Validate the Host header against an expected host allow-list at the edge."],
    "origin_confusion": ["Never authorize with tx.origin: it identifies the transaction origin, not the contract being called, so any intermediate contract can inherit it.", "Authorize with msg.sender against explicit owner/role checks.", "For proxy/upgrade paths, verify the caller through a trusted registry or owner slot."],
    "weak_randomness": ["Do not derive outcomes from block attributes (timestamp, number, difficulty, prevrandao, blockhash): every validator sees and mildly influences them.", "Use a commit-reveal scheme or a verifiable randomness source (VRF) for anything of value.", "Reserve block.timestamp for time constraints, never for results."],
    "unchecked_call_result": ["The low-level call family returns a success boolean that silently discards failure when ignored; check it and revert on false.", "Wrap in require(success, ...) so a failed value transfer or state change cannot pass unnoticed.", "Prefer a typed interface call over a raw call when the callee is known."],
}

def _priority(sev: str) -> str:
    return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(sev, "P3")

# 160 declarative rules from rules/enterprise_v1.yaml (the BIG4
# patch/extras layer folded into the YAML at migration; see
# tools/emit_rule_yaml.py).
ENTERPRISE_RULES: list[dict] = load_enterprise_rules()
_existing_rule_ids = {r.get("id") for r in ENTERPRISE_RULES}

# Backward-compatible existing rules retained. These are intentionally simple.
# 18 rules from rules/regex_v1.yaml; patterns compiled at load
# (core.regex_budget.timed_finditer takes a re.Pattern).
REGEX_RULES: list[dict] = load_regex_rules()


# Context-only heuristic rules are intentionally disabled from canonical SAST promotion.
# They are handled by framework/taint engines when sufficient context exists.
# Declarative: ids with disabled: true in the YAML.
DISABLED_CONTEXT_ONLY_RULES = _load_disabled_ids()

# ---- Big4 enterprise gap patch: rule hardening, evidence targeting, controls ----
BIG4_CONTROL_FALLBACKS = {
    "tls_bypass": {"pci_dss":"Req 4.2 / Req 6.2.4 - Protect transmission and prevent insecure crypto", "nist":"SC-8 / SC-13 / SI-10", "iso27001":"A.8.24 / A.8.20", "soc2":"CC6.7 / CC6.6"},
    "actuator_exposure": {"pci_dss":"Req 6.2.4 / Req 7 - Secure configuration and access control", "nist":"CM-7 / AC-3 / SC-7", "iso27001":"A.8.9 / A.8.20", "soc2":"CC6.6 / CC7.2"},
    "xxe": {"pci_dss":"Req 6.2.4 - Prevent XML external entity attacks", "nist":"SI-10 / SC-7", "iso27001":"A.14.2.5 / A.13.1.1", "soc2":"CC6.6 / CC7.2"},
    "redos": {"pci_dss":"Req 6.2.4 - Prevent resource exhaustion", "nist":"SC-5 / SI-10", "iso27001":"A.8.16 / A.8.20", "soc2":"CC7.2 / CC6.6"},
    "prototype_pollution": {"pci_dss":"Req 6.2.4 - Secure development", "nist":"SI-10 / CM-7", "iso27001":"A.8.28 / A.8.29", "soc2":"CC6.6 / CC7.2"},
    "async_security_context_loss": {"pci_dss":"Req 7 / Req 8 - Access control", "nist":"AC-3 / AC-6 / AU-12", "iso27001":"A.5.15 / A.8.2", "soc2":"CC6.1 / CC6.6"},
    "missing_validation": {"pci_dss":"Req 6.2.4 - Input validation", "nist":"SI-10", "iso27001":"A.8.28 / A.8.29", "soc2":"CC6.6"},
    "resource_exhaustion": {"pci_dss":"Req 6.2.4 / Req 8 - Abuse prevention", "nist":"AC-7 / SC-5 / SI-10", "iso27001":"A.8.16 / A.8.20", "soc2":"CC7.2 / CC6.6"},
    "race_condition": {"pci_dss":"Req 6.2.4 - Secure transaction processing", "nist":"SI-10 / AC-3", "iso27001":"A.8.28 / A.8.29", "soc2":"CC7.2 / CC6.6"},
    "template_injection": {"pci_dss":"Req 6.2.4 - Prevent injection attacks", "nist":"SI-10", "iso27001":"A.14.2.5", "soc2":"CC6.6"},
    "log_injection": {"pci_dss":"Req 10 / Req 6.2.4 - Secure logging", "nist":"AU-9 / SI-10", "iso27001":"A.8.15 / A.8.16", "soc2":"CC7.2 / CC7.4"},
    "zipslip": {"pci_dss":"Req 6.2.4 - File handling security", "nist":"SI-10 / AC-3", "iso27001":"A.8.28", "soc2":"CC6.6"},
}


# ---- Big4 enterprise gap patch ----
# T-0.6: BIG4_RULE_PATCHES / BIG4_REMEDIATION_BY_RULE /
# _EXTRA_BIG4_RULES moved into rules/enterprise_v1.yaml at
# migration (the emitter read the post-patch tables, so the YAML
# holds the final patterns/remediation verbatim). What remains is
# BIG4_CONTROL_FALLBACKS, the runtime compliance-text lookup.

# ---- PHP webshell / code-execution pack (G-PHP-WS) ----
# Additive: new ids only, no existing rule touched. Every pattern requires a
# request superglobal in the same statement as the sink, so benign calls
# (shell_exec("ls"), call_user_func("handler"), generated upload names) stay
# dark. Measured 2026-10-27: 16/16 webshell shapes detected, 0/15 benign
# controls flagged, 3 hits across 493 real PHP files (all DVWA upload
# sources). Rollback is one environment variable:
# RSECOPSX_PHP_WEBSHELL_RULES=0 -- no code change needed.
from scanner.php_webshell_rules import as_sast_rules as _php_ws_rules
for _r in _php_ws_rules():
    if _r["id"] not in _existing_rule_ids:
        ENTERPRISE_RULES.append(_r)
        _existing_rule_ids.add(_r["id"])
# ---- end PHP webshell pack ----

COMPILED_ENTERPRISE_RULES = [
    {**r, "pattern": re.compile(r["pat"], _F)}
    for r in ENTERPRISE_RULES
    if r.get("id") not in DISABLED_CONTEXT_ONLY_RULES
]


def _skip(path: Path) -> bool:
    # T-0.2: the policy lives in core.file_index (the one walk applies it
    # once for every engine); this wrapper keeps the historical name.
    return file_index.skip_path(path)


def _should_scan(path: Path) -> bool:
    name = path.name
    return (
        (path.suffix.lower() in {str(ext).lower() for ext in SCANNABLE_EXT}
         or name in SCANNABLE_EXT)
        and not _skip(path)
    )


# Third-party SCANNER-RESULT exports. These are tool output, not application
# source: a findbugs/spotbugs ``BugCollection`` embeds HTML-escaped Java source
# excerpts in its <LongMessage>, ZAP embeds scanned-page evidence, and the
# sonar/visualcodegrepper/pmd exports embed rule matches. Reading them as if
# they were code produced false secrets and hash-usage findings on the BENCHMARK
# REPO'S OWN shipped result files (6 findings in BenchmarkJava's results/*.xml).
# Detection is by ROOT ELEMENT — unambiguous tool signatures — never by
# extension or directory name, so a real application <config>/<settings> XML is
# still scanned in full.
_SCANNER_RESULT_XML_ROOTS = frozenset({
    "BugCollection",       # findbugs / spotbugs / findsecbugs
    "FindBugsSummary",     # spotbugs summary export
    "OWASPZAPReport",      # ZAP scan report
    "CodeIssueCollection", # visualcodegrepper
    "pmd",                 # PMD
})


# T-0.2: moved to core.file_index so the one walk applies it once for every
# engine; the historical name is kept (analysis/validation/brain.py imports it).
_is_scanner_result_json = file_index._is_scanner_result_json


def _is_scanner_result_xml(path: Path) -> bool:
    """True when the file is a third-party scanner-result XML export.

    Reads only a small header (the root element lives at the top), so this is
    cheap even for the 17-64 MB result files BenchmarkJava ships. The sonar
    web-API export uses a generic ``<total>`` root, so it additionally requires
    the corroborating ``<issues>`` + ``<component>`` siblings that only that
    export carries.
    """
    if path.suffix.lower() != ".xml":
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    stripped = re.sub(r"<\?xml[^>]*\?>", "", head, count=1).lstrip()
    m = re.match(r"<([A-Za-z_][\w:.-]*)", stripped)
    if not m:
        return False
    root = m.group(1)
    if root in _SCANNER_RESULT_XML_ROOTS:
        return True
    # SonarQube web-API export: root <total> plus <issues>/<component> children.
    if root == "total" and "<issues>" in head and "<component>" in head:
        return True
    return False


def _language(path: Path) -> str:
    if path.name == "Dockerfile":
        return "dockerfile"
    return LANG_BY_EXT.get(path.suffix.lower(), path.suffix.lower().lstrip(".") or "unknown")


def _line_for(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


_LINE_COMMENT_PREFIXES = {
    "python": ("#",),
    "ruby": ("#",),
    "shell": ("#",),
    "yaml": ("#",),
    "dockerfile": ("#",),
    "properties": ("#", ";"),
    "javascript": ("//",),
    "typescript": ("//",),
    "java": ("//",),
    "kotlin": ("//",),
    "scala": ("//",),
    "go": ("//",),
    "csharp": ("//",),
    "c": ("//",),
    "cpp": ("//",),
    "php": ("//", "#"),
    "solidity": ("//",),
    "vbnet": ("'",),
    "xml": ("<!--",),
    "graphql": ("#",),
}

_BLOCK_COMMENT_DELIMS = {
    "javascript": ("/*", "*/"),
    "typescript": ("/*", "*/"),
    "java": ("/*", "*/"),
    "kotlin": ("/*", "*/"),
    "scala": ("/*", "*/"),
    "go": ("/*", "*/"),
    "csharp": ("/*", "*/"),
    "c": ("/*", "*/"),
    "cpp": ("/*", "*/"),
    "solidity": ("/*", "*/"),
    "php": ("/*", "*/"),
    "xml": ("<!--", "-->"),
}


def _is_comment(snippet: str, language: str) -> bool:
    """Return True only for a language-valid comment-only evidence snippet."""
    s = str(snippet or "").strip()
    if not s:
        return True

    lang = str(language or "").lower()
    prefixes = _LINE_COMMENT_PREFIXES.get(lang, ())
    if any(s.startswith(prefix) for prefix in prefixes):
        return True

    # A leading '*' is meaningful only as a continuation of a C-style/XML
    # block comment; it is not a comment marker in Python or C/C++ code.
    if s.startswith("*") and lang in _BLOCK_COMMENT_DELIMS:
        return True

    return False


def _match_starts_in_comment(source: str, offset: int, language: str) -> bool:
    """
    Determine whether a regex match begins inside a comment.

    Multiline enterprise regexes can span code and comments, so inspecting only
    the selected evidence line is unsafe. This lightweight lexical scan tracks
    language-valid line/block comments and skips quoted strings.
    """
    if offset < 0:
        return False

    lang = str(language or "").lower()
    line_prefixes = _LINE_COMMENT_PREFIXES.get(lang, ())
    block = _BLOCK_COMMENT_DELIMS.get(lang)

    if not line_prefixes and not block:
        return False

    block_start, block_end = block if block else (None, None)
    in_block = False
    i = 0
    n = min(offset, len(source))

    while i < n:
        if in_block:
            end = source.find(block_end, i, n)
            if end == -1:
                return True
            in_block = False
            i = end + len(block_end)
            continue

        if line_prefixes and any(source.startswith(marker, i) for marker in line_prefixes):
            nl = source.find("\n", i, n)
            if nl == -1:
                return True
            i = nl + 1
            continue

        if block_start and source.startswith(block_start, i):
            in_block = True
            i += len(block_start)
            continue

        # Ignore comment-looking text inside quoted strings.
        ch = source[i]
        if ch in {"\"", "'"}:
            quote = ch
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        i += 1

    if in_block:
        return True

    # A line-comment marker before the match means the remainder of that line
    # is comment text, even when the line also contains executable code.
    line_start = source.rfind("\n", 0, offset) + 1
    prefix = source[line_start:offset]
    return any(marker in prefix for marker in line_prefixes)





def _match_starts_in_python_string(source: str, offset: int, language: str) -> bool:
    """Return True when a Python regex match begins inside a string/docstring."""
    if str(language or "").lower() not in {"python", "py"}:
        return False
    if offset < 0:
        return False

    try:
        lines = source.splitlines(keepends=True)

        # Build absolute character offsets for tokenize's (row, column)
        # coordinates.
        line_offsets = []
        total = 0
        for line in lines:
            line_offsets.append(total)
            total += len(line)

        def absolute(pos):
            row, col = pos
            if row <= 0 or row > len(line_offsets):
                return None
            return line_offsets[row - 1] + col

        for tok in tokenize.generate_tokens(iter(lines).__next__):
            if tok.type == tokenize.STRING:
                start = absolute(tok.start)
                end = absolute(tok.end)

                if start is not None and end is not None:
                    if start <= offset < end:
                        return True

    except (tokenize.TokenError, IndentationError, SyntaxError, StopIteration):
        return False
    except Exception:
        return False

    return False

def _snippet_for_match(rule: dict, source: str, lines: list[str], start: int, end: int) -> tuple[int, str]:
    """Return the most meaningful evidence line for a multiline rule match."""
    evidence_pat = rule.get("evidence_pat")
    segment = source[start:end]
    if evidence_pat:
        em = re.search(evidence_pat, segment, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if em:
            offset = start + em.start()
            line = _line_for(source, offset)
            return line, (lines[line - 1].strip() if line <= len(lines) else em.group(0).strip())
    # Prefer the line containing a dangerous sink/config rather than an import/header line.
    focus_patterns = [
        r"parseExpression\s*\(", r"include\s*[:=]\s*[\"']?\*[\"']?",
        r"enableDefaultTyping", r"activateDefaultTyping", r"TypeNameHandling",
        r"InsecureSkipVerify", r"DangerousAcceptAnyServerCertificateValidator",
        r"setAccessible\s*\(", r"fromXML\s*\(", r"\.load\s*\(",
        r"ExtractToDirectory", r"ExtractToFile", r"curl_setopt", r"CURLOPT_SSL",
        r"introspection\s*:\s*true", r"graphiql\s*:\s*true", r"__schema",
        r"depthLimit", r"complexity", r"new\s+Function\s*\(", r"eval\s*\(",
        r"vm\.runIn", r"unserialize\s*\(", r"gob\.NewDecoder", r"json\.Unmarshal",
        r"ZipFile", r"ZipEntry", r"file_exists", r"existsSync"
    ]
    base_line = _line_for(source, start)
    for idx, txt in enumerate(segment.splitlines()):
        if any(re.search(pat, txt, re.I) for pat in focus_patterns):
            line = base_line + idx
            return line, txt.strip()
    line = _line_for(source, start)
    return line, (lines[line - 1].strip() if line <= len(lines) else segment.strip().splitlines()[0] if segment.strip() else "")

def _match_starts_in_javascript_comment(source: str, offset: int, language: str) -> bool:
    """Return True when a JavaScript/TypeScript regex match starts inside // or /* */ comments."""
    if str(language or "").lower() not in {"javascript", "typescript"}:
        return False

    if offset < 0:
        return False

    line_start = source.rfind("\n", 0, offset) + 1
    line_prefix = source[line_start:offset]

    # Single-line JavaScript/TypeScript comment.
    # Ignore // appearing inside a quoted string.
    quote = None
    escaped = False
    i = 0

    while i < len(line_prefix):
        ch = line_prefix[i]

        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        else:
            if ch in {"'", '"', "`"}:
                quote = ch
            elif ch == "/" and i + 1 < len(line_prefix) and line_prefix[i + 1] == "/":
                return True

        i += 1

    # Block JavaScript/TypeScript comment.
    block_start = source.rfind("/*", 0, offset)
    block_end = source.rfind("*/", 0, offset)

    return block_start > block_end


def _match_starts_in_javascript_string(source: str, offset: int, language: str) -> bool:
    """Return True when a JavaScript/TypeScript regex match starts inside a string."""
    if str(language or "").lower() not in {"javascript", "typescript"}:
        return False

    if offset < 0:
        return False

    quote = None
    escaped = False
    i = 0

    while i < min(offset, len(source)):
        ch = source[i]

        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        else:
            if ch in {"'", '"', "`"}:
                quote = ch

        i += 1

    return quote is not None


def _match_starts_in_php_string(source: str, offset: int, language: str) -> bool:
    """Return True when a PHP regex match starts inside a string/heredoc.

    Batch-10 lesson (DVWA csp/source/high.php): the word ``include`` appears
    as the PARAMETER NAME ``$_POST['include']``, so a keyword-sink pattern
    whose validator only inspects the extracted statement fired on the quoted
    name. A php string position is not code; every batch-10 php rule anchors
    on real code, so the position check is a pure false-positive guard.
    Handles '...' / "..." / backtick strings (backslash escapes), // and #
    line comments, /* */ blocks and heredoc/nowdoc bodies.
    """
    if str(language or "").lower() not in {"php"}:
        return False
    if offset < 0:
        return False

    quote = None
    escaped = False
    heredoc_label = None
    i = 0
    n = min(offset, len(source))

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if heredoc_label is not None:
            if ch == "\n":
                j = i + 1
                k = j
                while k < n and source[k] in " \t":
                    k += 1
                if source.startswith(heredoc_label, k):
                    i = k + len(heredoc_label) - 1
                    heredoc_label = None
            i += 1
            continue

        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            i = n if end == -1 or end > n else end
            continue
        if ch == "#":
            end = source.find("\n", i)
            i = n if end == -1 or end > n else end
            continue
        if ch == "/" and nxt == "*":
            end = source.find("*/", i + 2)
            i = n if end == -1 or end + 1 > n else end + 1
            continue
        if ch == "<" and source.startswith("<<<", i):
            m = re.match(r"<<<\s*(['\"]?)([A-Za-z_]\w*)\1\r?\n", source[i:])
            if m:
                heredoc_label = m.group(2)
                i += m.end() - 1
                continue
        if ch in {"'", '"', "`"}:
            quote = ch

        i += 1

    return quote is not None or heredoc_label is not None



def _is_intentional_dynamic_import_function(source: str, match: re.Match) -> bool:
    """Exclude a fixed Function() wrapper used only to invoke dynamic import.

    This pattern is not code injection when both the generated function body and
    its parameter list are static; the imported module specifier is data passed
    to native import(), not executable source code.
    """
    start = max(0, match.start() - 80)
    end = min(len(source), match.end() + 220)
    ctx = source[start:end]
    return bool(re.search(
        r"new\s+Function\s*\(\s*['\"]specifier['\"]\s*,\s*['\"]return\s+import\s*\(\s*specifier\s*\)['\"]\s*\)",
        ctx, re.I | re.S,
    ))


# Explicit XXE hardening the file already applies to its parser. Measured
# against OWASP BenchmarkJava: all 35 files constructing a
# DocumentBuilderFactory setFeature("...disallow-doctype-decl", true)
# immediately afterwards, and the XXE rule -- matching only the
# newInstance() constructor -- reported all 35 as High XXE, 20 of them on
# tests the oracle labels negative. Every XXE finding the rule produced
# against that benchmark was against a file carrying the canonical
# mitigation. Whole-file matching rather than bounded context: hardening
# is a rare, deliberate API call, and a parser factory built next to a
# hardened one in the same file is beyond what this regex layer models.
_JAVA_XXE_HARDENED_RE = re.compile(
    r"disallow-doctype-decl"
    r"|load-external-dtd"
    r"|FEATURE_SECURE_PROCESSING"
    r"|setExpandEntityReferences\s*\(\s*false"
    r"|IS_SUPPORTING_EXTERNAL_ENTITIES\s*[\"']?\s*,\s*false",
    re.I,
)


def _java_xxe_parser_hardened(source: str) -> bool:
    """True when the file already hardens its XML parser against XXE."""
    return bool(_JAVA_XXE_HARDENED_RE.search(source))


# --- V1.12b: value gate for the Java file-access window rule ---------------
# JAVA_PATH_TRAVERSAL_FILE's window regex matches the substring ``filename``
# (case-insensitively) inside a variable NAME such as ``fileName`` -- it asks
# nothing about the value that reaches ``Paths.get``/``new File``. Measured
# against the BenchmarkJava oracle (findings13 attribution) that produced 16
# firings on negative tests, every one of them a call whose argument provably
# folds to a compile-time constant: map strong update, switch pruning on a
# folded selector, constant ternary, literal-returning helper. The same
# bounded evaluator V1.12a used for TAINT_MULTIPART_TRAVERSAL answers the
# value question, kill-only-on-proof: every identifier inside the call's
# parentheses must be PROVEN constant at the sink line, else the finding is
# kept. String literals inside the argument list are constants by definition
# (and cannot smuggle identifiers into the proof); a pure-literal call keeps
# the finding because there is no identifier to prove and no measurement
# demanded the kill. Unbalanced parentheses, casts, qualified names that do
# not resolve, method calls, unresolved variables and evaluator budget all
# keep. ``RSX_MULTIPART_FLOW=0`` disables the shared evaluator and therefore
# this gate.
_JAVA_PATH_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_JAVA_PATH_STR_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_JAVA_PATH_CHAR_RE = re.compile(r"'(?:[^'\\]|\\.)*'")
_JAVA_PATH_PAREN_WINDOW = 64


def _java_path_arg_proven_constant(source: str, match, filepath: str) -> bool:
    """True only when EVERY identifier in the matched file-call's argument
    list is a proven compile-time constant at the sink line.

    Kill-only-on-proof: any ambiguity (unbalanced parens, no identifier to
    prove, unprovable identifier, evaluator failure) returns False, which
    callers turn into KEEP. Never raises.
    """
    try:
        open_idx = source.find(
            "(", match.start(),
            match.start() + _JAVA_PATH_PAREN_WINDOW)
        if open_idx == -1:
            return False
        # Scan forward, string/char-literal aware, to the matching ")".
        depth = 0
        i = open_idx
        n = len(source)
        quote = None
        while i < n:
            ch = source[i]
            if quote is not None:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            return False  # unbalanced: not provable -> KEEP
        if depth != 0:
            return False
        args = _JAVA_PATH_CHAR_RE.sub(
            " ", _JAVA_PATH_STR_RE.sub(" ", source[open_idx + 1:i]))
        idents = _JAVA_PATH_IDENT_RE.findall(args)
        if not idents:
            return False  # pure literal: keep (nothing to prove)
        from scanner.multipart_flow import is_proven_constant
        at_line = source.count("\n", 0, match.start()) + 1
        for ident in idents:
            if not is_proven_constant(source, ident, at_line, filepath):
                return False
        return True
    except Exception:
        return False


def _is_client_side_ssrf_context(filepath: str, line: str) -> bool:
    """Return True when an SSRF candidate is clearly browser/client-side code.

    The NODE_SSRF_DYNAMIC_URL rule is intentionally broad so that genuine
    server-side Node/TypeScript SSRF remains detectable.  Browser-side Axios,
    fetch, React components, and frontend API helpers cannot by themselves
    establish server-side SSRF because the outbound request executes in the
    user's browser.
    """
    path = str(filepath or "").replace("\\", "/").lower()
    text = str(line or "")

    # Strong path-based indicators of browser/client-side code.
    if (
        "/frontend/" in path
        or "/client/" in path
        or "/web/" in path
        or "/src/api/" in path
        or path.endswith((
            "/axios.js",
            "/axios.jsx",
            "/axios.ts",
            "/axios.tsx",
        ))
    ):
        return True

    # Browser/React indicators when the path alone is not sufficient.
    return bool(re.search(
        r"\b(?:window|document|localStorage|sessionStorage)\b"
        r"|\b(?:useEffect|useQuery|useMutation)\s*\(",
        text,
        re.I,
    ))


def _is_rate_limit_endpoint_match(source: str, match: re.Match, language: str) -> bool:
    """Accept an abuse-prone path only when it appears in a server route declaration."""
    start, end = match.start(), match.end()
    line_start = source.rfind("\n", 0, start) + 1
    line_end = source.find("\n", end)
    if line_end == -1:
        line_end = len(source)
    line = source[line_start:line_end]

    # Do not treat frontend navigation or client-side API references as endpoints.
    if re.search(
        r'(?:\b(?:Navigate|Link|NavLink)\b[^\n]{0,180}\bto\s*='
        r'|\b(?:axios|api|client|http|fetch|XMLHttpRequest)\s*(?:\.\s*(?:get|post|put|patch|delete|request))?\s*\('
        r'|\burl\s*\.\s*includes\s*\('
        r'|\b(?:href|to)\s*[:=]\s*["\']/(?:login|otp|password-reset|reset|invite|coupon|refresh|payment)\b)',
        line, re.I
    ):
        return False

    # Keep the context local enough to avoid unrelated routes elsewhere in a file.
    ctx = source[max(0, start - 700):min(len(source), end + 900)]

    if language == "python":
        return bool(re.search(
            r'@(?:app|router|api|bp)\.(?:route|get|post|put|patch|delete|api_route)\s*\('
            r'|(?:^|[^\w])(?:path|re_path)\s*\(\s*[rRuU]?["\']'
            r'|@(?:app|router)\.add_api_route\s*\(',
            ctx, re.I | re.M
        ))

    if language in {"javascript", "typescript"}:
        return bool(re.search(
            r'\b(?:app|router|api|server)\s*\.\s*(?:get|post|put|patch|delete|all|use|route)\s*\('
            r'|\b(?:fastify|server)\s*\.\s*(?:route|get|post|put|patch|delete)\s*\(',
            ctx, re.I
        ))

    if language == "java":
        return bool(re.search(
            r'@(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\([^)]*'
            r'|RouterFunctions\s*\.\s*route\s*\(',
            ctx, re.I
        ))

    if language == "csharp":
        return bool(re.search(
            r'\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\s*(?:\([^)]*)?\]'
            r'|\.Map(?:Get|Post|Put|Patch|Delete)\s*\(',
            ctx, re.I
        ))

    if language == "go":
        return bool(re.search(
            r'http\.(?:HandleFunc|Handle)\s*\('
            r'|\b(?:mux|router|r|chi|gin|echo)\s*\.\s*(?:Handle|HandleFunc|Get|Post|Put|Patch|Delete|Any)\s*\(',
            ctx, re.I
        ))

    if language == "php":
        return bool(re.search(
            r'\bRoute\s*::\s*(?:get|post|put|patch|delete|match|any)\s*\('
            r'|#\[\s*Route\s*\(',
            ctx, re.I
        ))

    return False


def _rate_limit_present(source: str, match: re.Match) -> bool:
    """Detect a nearby explicit rate-limit/throttling control."""
    ctx = source[max(0, match.start() - 900):min(len(source), match.end() + 1200)]
    return bool(re.search(
        r'(?:rateLimit|rateLimiter|RateLimiter|throttle|Throttle|Bucket4j|limit_req'
        r'|slow_down|express-rate-limit|django-ratelimit|@RateLimiter|@Throttle|@rate[_-]?limit\s*\(|Limiter)',
        ctx, re.I
    ))


def _aliased_hashlib_match(source: str, match: re.Match, rule: dict, language: str = "") -> bool:
    """Gate the bare ``md5(`` / ``sha1(`` arm of MD5_USAGE / SHA1_USAGE.

    The qualified arms (``hashlib.md5(``, ``MessageDigest.getInstance("MD5")``,
    ``crypto.createHash('md5')``, ``MD5CryptoServiceProvider``) are unambiguous.
    The trailing bare-call arm only denotes the hashlib algorithm when the file
    imports that exact name from hashlib -- ``from hashlib import md5`` then
    calling ``md5(...)`` (pygoat introduction/mitre.py:161, CNAP
    CRYPTO-WEAK-003). A local helper named md5()/sha1() with no hashlib import
    is not weak crypto and stays quiet.

    2026-10-21 batch 9 (DVWA): PHP's ``md5()``/``sha1()`` ARE the hash
    functions with no import ceremony (DVWA mysql.php sha1($password), CNAP
    CRYPTO-WEAK-003 x20), so the bare arm passes for php directly.
    """
    head = match.group(0)
    name = "md5" if rule.get("id") == "MD5_USAGE" else "sha1"
    if not head.lower().startswith(name):
        # qualified arm (hashlib.md5(, MessageDigest..., createHash...)
        return True
    if language == "php":
        return True
    return bool(re.search(
        r"from\s+hashlib\s+import\s+[^#\n]*\b" + name + r"\b", source
    ))


# Per-rule "this kwarg is missing from the set_cookie() call" guards. One rule
# per flag keeps the finding's CWE (614/1004/1275) exact, mirroring the Java
# servlet cookie rule's per-flag decomposition.
_PY_COOKIE_FLAG_BY_RULE = {
    "PY_COOKIE_MISSING_SECURE": r"(?<![\w-])secure\s*=",
    "PY_COOKIE_MISSING_HTTPONLY": r"(?<![\w-])httponly\s*=",
    "PY_COOKIE_MISSING_SAMESITE": r"(?<![\w-])samesite\s*=",
}


def _call_region(source: str, start: int, cap: int = 2000) -> str:
    """Text of the parenthesised call beginning at/below ``start``."""
    paren = source.find("(", start)
    if paren == -1:
        return ""
    depth = 0
    i = paren
    while i < len(source) and i - paren < cap:
        c = source[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return source[paren:i + 1]
        i += 1
    return source[paren:paren + cap]


def _py_cookie_flag_missing(source: str, match: re.Match, language: str, flag_re: str) -> bool:
    """True when the framework set_cookie() call lacks the rule's flag.

    Gates: python only, and the file must name flask/django -- a bespoke
    object's set_cookie() method is not the framework cookie API.
    """
    if language != "python":
        return False
    if not re.search(r"\b(?:flask|django)\b", source, re.I):
        return False
    region = _call_region(source, match.start(), cap=1500)
    if not region:
        return False
    return not re.search(flag_re, region, re.I)


def _express_session_no_expiry(source: str, match: re.Match, language: str) -> bool:
    """True when an express-session config block sets no cookie lifetime.

    The region scan (not a file-wide text search) is what keeps the NodeGoat
    ``// TODO: Add "maxAge"`` comment inside the config block from masking the
    finding: the comment contains the word maxAge but no ``maxAge:`` property.
    """
    if language not in {"javascript", "typescript"}:
        return False
    if "express-session" not in source:
        return False
    depth = 0
    started = False
    end = min(len(source), match.start() + 3000)
    for j in range(match.start(), end):
        c = source[j]
        if c in "({":
            depth += 1
            started = True
        elif c in ")}":
            depth -= 1
            if started and depth <= 0:
                end = j + 1
                break
    region = source[match.start():end]
    return not re.search(r"\b(?:maxAge|expires)\s*:", region, re.I)


def _java_cbc_static_iv(source: str, match: re.Match, language: str) -> bool:
    """True for a CBC cipher call whose IV is a literal (wrongsecrets batch 9).

    Challenge54.java assigns ``byte[] ivBytes = "0123456789abcdef"...`` one
    line above the Cipher.getInstance call; Challenge63 assigns a constant
    whose NAME ends in IV. Both shapes need a window scan: the literal is
    never on the sink line. GCM/SecureRandom shapes carry no IvParameterSpec
    in the window and stay quiet.
    """
    if language != "java":
        return False
    # +-1500 chars: in wrongsecrets Challenge63 the IV literal sits in the
    # class-constant block ~580 chars above the sink -- a 600-char window
    # only catches it by luck, and other challenge files mount constants
    # further away.
    lo = max(0, match.start() - 1500)
    hi = min(len(source), match.end() + 1500)
    window = source[lo:hi]
    if "IvParameterSpec" not in window:
        return False
    return bool(
        re.search(r"(?i)\w*iv\w*\s*=\s*[\"'][^\"']{8,}[\"']", window)
        or re.search(r"IvParameterSpec\s*\(\s*[\"']", window)
    )


# PHP setcookie is positional: secure is argument 6, httponly argument 7
# (PHP docs; the 7.3+ options-array form names them instead).
_PHP_COOKIE_FLAG_BY_RULE = {
    "PHP_COOKIE_MISSING_SECURE": ("secure", 6),
    "PHP_COOKIE_MISSING_HTTPONLY": ("httponly", 7),
}


def _php_cookie_flag_missing(source: str, match: re.Match, language: str, need: str) -> bool:
    """True when the setcookie() call lacks the rule's flag (DVWA batch 9).

    Handles both the positional form (count top-level commas, quote- and
    bracket-aware) and the PHP 7.3+ ``[... 'secure' => true ...]`` options
    array (presence of the key satisfies, regardless of value -- presence
    semantics, same as the python cookie rules).
    """
    if language != "php":
        return False
    region = _call_region(source, match.start(), cap=1500)
    if not region or len(region) < 3:
        return False
    if re.search(r"[\"']" + need + r"[\"']\s*=>", region, re.I):
        return False
    depth = 0
    commas = 0
    quote = None
    for ch in region[1:-1]:
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            commas += 1
    argc = commas + 1
    min_argc = 6 if need.lower() == "secure" else 7
    return argc < min_argc


# --- batch-10 (2026-10-21): request-derived-value helpers + validators ------
#
# Batch 8-9 rules all required the SUPERGLOBAL itself on the sink line. Every
# remaining confirmed CNAP true positive in the batch-10 joins (WebGoat SQLi,
# DVWA sqli/weak_id/exec/open_redirect/view_source/jsonp, railsgoat
# secret_token.rb) instead feeds the sink through a VARIABLE assigned a few
# lines above. The helpers below implement a bounded backward scan over the
# preceding window: an identifier is request-derived when its own assignment
# RHS touches a request source ($_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES,
# $_SERVER HTTP_/QUERY_/REQUEST_ keys, php://input), optionally propagating
# one more hop through referencing assignments. ``passes=1`` keeps one-hop
# chains dark by design -- that is what lets the adjudicated CNAP false
# positives (DVWA instructions.php whitelist lookup, check_token_high.php
# processed-body print) stay quiet without a special case.

_PHP_REQUEST_SOURCE_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
    r"|\$_SERVER\s*\[\s*[\"'](?:HTTP_|QUERY_STRING|REQUEST_URI)"
    r"|php://input")

# A1b (2026-10-22, DVWA sqli/source/high.php vs CNAP INJ-SQL-001): a
# $_SESSION value is request-derived ONLY when some file in the corpus
# assigns it from a request source (session-input.php:
# `$_SESSION['id'] = $_POST['id']`). Session state is otherwise server-set
# (login rows from the database, flash data), which is why $_SESSION is not
# a general request source -- but DVWA's high-security SQLi variant routes
# the POST through the session and then interpolates it into the query, so
# rejecting the superglobal outright left a genuine injection dark. The
# corpus pre-pass below proves, per scan, exactly which keys carry request
# data; unproven keys keep the old quiet behavior.
_CORPUS_SESSION_SOURCE_KEYS: set = set()

_SESSION_ASSIGN_RE = re.compile(
    r"\$_SESSION\s*\[\s*['\"]([\w\-]+)['\"]\s*\]\s*=\s*([^;\n]+)")

# Cache for the request-source regex extended with corpus-proven session
# keys. Rebuilt only when the proven-key set changes (per scan_directory
# pre-pass); concurrent workers may race the rebuild benignly -- they all
# compute the same regex for the same key snapshot.
_DIRECT_SOURCE_CACHE = {"keys": None, "re": _PHP_REQUEST_SOURCE_RE}


def _collect_corpus_session_keys(target) -> set:
    """Pre-pass over a corpus: $_SESSION keys proven request-derived.

    A key qualifies when some php file assigns it from a request source
    either directly (`$_SESSION['id'] = $_POST['id']`) or through a bounded
    two-pass variable closure (`$id = $_POST['id']; $_SESSION['id'] = $id`)
    -- the same semantics as _php_tainted_vars, per file. The resulting set
    is published module-wide for the scan_file workers (read-only once the
    pool starts). Any read failure simply yields fewer proven keys.
    """
    keys: set = set()
    try:
        # T-0.2: the one walk already applied the skip policy; no re-walk.
        php_files = file_index.index_for(target).files(exts={".php"})
    except OSError:
        php_files = []
    for fp in php_files:
        try:
            text = file_index.read_source(fp)
        except OSError:
            continue
        if text is None:
            continue
        assignments = re.findall(r"\$([A-Za-z_]\w*)\s*=\s*([^;\n]+)", text)
        tainted: set = set()
        for _ in range(2):
            grew = False
            for name, rhs in assignments:
                if name in tainted:
                    continue
                if _PHP_REQUEST_SOURCE_RE.search(rhs) or any(
                        re.search(r"\$" + re.escape(t) + r"\b", rhs)
                        for t in tainted):
                    tainted.add(name)
                    grew = True
            if not grew:
                break
        for key, rhs in _SESSION_ASSIGN_RE.findall(text):
            if _PHP_REQUEST_SOURCE_RE.search(rhs) or any(
                    re.search(r"\$" + re.escape(t) + r"\b", rhs)
                    for t in tainted):
                keys.add(key)
    _CORPUS_SESSION_SOURCE_KEYS.clear()
    _CORPUS_SESSION_SOURCE_KEYS.update(keys)
    return keys


def _php_direct_source_re():
    """Request sources for the php validators: request superglobals plus
    corpus-proven session keys (never matches when no keys were proven)."""
    snap = frozenset(_CORPUS_SESSION_SOURCE_KEYS)
    if _DIRECT_SOURCE_CACHE["keys"] != snap:
        if snap:
            _DIRECT_SOURCE_CACHE["re"] = re.compile(
                _PHP_REQUEST_SOURCE_RE.pattern
                + r"|\$_SESSION\s*\[\s*['\"](?:%s)['\"]\s*\]"
                % "|".join(re.escape(k) for k in sorted(snap)))
        else:
            _DIRECT_SOURCE_CACHE["re"] = _PHP_REQUEST_SOURCE_RE
        _DIRECT_SOURCE_CACHE["keys"] = snap
    return _DIRECT_SOURCE_CACHE["re"]

# Wrappers whose output is encoded/safe: when the tainted value only occurs
# inside one of these calls the echo/print/file statement is not an injection.
_PHP_SAFE_WRAPPER_RE = re.compile(
    r"(?:htmlspecialchars|htmlentities|strip_tags|json_encode|intval"
    r"|addslashes|escapeshellarg|escapeshellcmd)\s*\((?:[^()]|\([^()]*\))*\)")


def _php_tainted_vars(source: str, anchor: int, window: int = 1500,
                      passes: int = 1) -> set:
    """Identifiers ($-stripped) whose assignment RHS is request-derived.

    Scans backwards from ``anchor`` over a bounded window, collecting
    ``$name = ...`` assignments. With ``passes > 1`` an identifier whose RHS
    merely references an already-derived identifier also becomes derived
    (php://input json body: ``$input = json_decode(file_get_contents(
    'php://input'))`` then ``$target = $input['target']``).
    """
    lo = max(0, anchor - window)
    region = source[lo:anchor]
    assignments = re.findall(r"\$([A-Za-z_]\w*)\s*=\s*([^;\n]+)", region)
    tainted: set = set()
    for _ in range(max(1, passes)):
        grew = False
        for name, rhs in assignments:
            if name in tainted:
                continue
            if _php_direct_source_re().search(rhs):
                tainted.add(name)
                grew = True
            elif passes > 1 and any(
                    re.search(r"\$" + re.escape(t) + r"\b", rhs)
                    for t in tainted):
                tainted.add(name)
                grew = True
        if not grew:
            break
    return tainted


def _php_statement(source: str, match: re.Match, cap: int = 500) -> str:
    """Statement text from the match to the next top-level ';' (bounded)."""
    end = source.find(";", match.start())
    if end == -1 or end - match.start() > cap:
        end = min(len(source), match.start() + cap)
    return source[match.start():end]


def _php_tainted_in(text: str, tainted: set) -> bool:
    return any(re.search(r"\$" + re.escape(t) + r"\b", text) for t in tainted)


# Sink taxonomy for the report-side EVIDEX evidence contract. These rules
# emit regex findings with no taint-engine path, so without a recorded
# sink_category/taint_path the analyzer's evidence gate (expected-vs-candidate
# sink intersection, then the path_traversal occurrence gate in main.py)
# deleted every finding at report intake -- measured on the DVWA re-scan:
# all 21 path, 3 redirect and 1 xss rows were produced by scan_directory and
# silently dropped before clean_report.json. The chain recorded here is the
# validator's own window analysis (which variable, fed from which request
# source, reaches which sink), so downstream taint-evidence gates treat the
# finding as the source-to-sink evidence it actually is.
# T-0.6: 7 categories declarative (rules/enterprise_v1.yaml
# sink_category) + 8 from the webshell pack's own map; EVIDEX
# deletes a regex finding with no sink category at intake, so the
# pack's entries travel with the pack.
from scanner.php_webshell_rules import SINK_CATEGORIES as _PHP_WS_SINK
_PHP_SINK_CATEGORY = {**load_sink_categories(), **_PHP_WS_SINK}


# Batch-10 php rules subject to the string-position guard (see dispatch).
_BATCH10_PHP_RULE_IDS = frozenset(_PHP_SINK_CATEGORY) | {
    "PHP_SESSION_ID_PREDICTABLE",
}


def _php_rule_taint_chain(rule_id: str, source: str, match: re.Match) -> str:
    """Record which request source reaches the sink, per rule family."""
    if rule_id in ("PHP_CMD_INJECTION_INTERMEDIATE",
                   "PHP_SQL_INTERMEDIATE_QUERY"):
        # 2-hop window: the json-body form chains input -> decode -> sink
        # (cmd: exec; sql: the intermediate query variable).
        tainted = _php_tainted_vars(source, match.start(), passes=2)
    else:
        tainted = _php_tainted_vars(source, match.start(), passes=1)
    stmt = _php_statement(source, match)
    for t in sorted(tainted):
        if re.search(r"\$" + re.escape(t) + r"\b", stmt):
            return "$%s -> %s" % (t, match.group(0).split("(")[0].strip())
    if rule_id == "PHP_SQL_INTERMEDIATE_QUERY":
        # The sink argument is itself an intermediate variable: the
        # request-derived operand sits in THAT variable's assignment (one
        # hop further up than the sink statement). Proven here so the
        # EVIDEX evidence gate sees a real source-to-sink chain.
        region = source[max(0, match.start() - 1500):match.start()]
        for t in sorted(tainted):
            for nm in set(re.findall(r"\$([A-Za-z_]\w*)", stmt)):
                am = re.search(
                    r"\$" + re.escape(nm) + r"\b\s*=\s*([^;\n]+)", region)
                if am and re.search(r"\$" + re.escape(t) + r"\b", am.group(1)):
                    return "$%s -> %s" % (
                        t, match.group(0).split("(")[0].strip())
    # Direct superglobal at the sink (no variable hop): name it as the source.
    m = _php_direct_source_re().search(stmt)
    if m:
        return "%s -> %s" % (m.group(0).split("[")[0].strip(),
                             match.group(0).split("(")[0].strip())
    return ""


def _java_sql_intermediate_query(source: str, match: re.Match, language: str) -> bool:
    """WebGoat shape: ``String query = \"...\" + param; executeQuery(query)``.

    Fires only when the bare-identifier sink argument was assigned, within the
    preceding window, a string that contains a SQL keyword AND concatenates a
    non-literal operand, and the window carries request-parameter evidence
    (@RequestParam/@PathVariable/@RequestBody/@ModelAttribute/getParameter)
    plus JDBC context. Fully-literal query variables, parameterised '?'
    forms and non-JDBC ``executor.execute(task)`` stay dark.
    """
    if language != "java":
        return False
    gd = match.groupdict() or {}
    var = gd.get("jvar") or gd.get("pvar") or ""
    if not var:
        return False
    lo = max(0, match.start() - 1500)
    window = source[lo:match.start()]
    # JDBC context: the window must name a JDBC statement call, EXCEPT when
    # the matched sink itself is prepareStatement(queryString, ...) -- the
    # call is its own context (WebGoat Lesson5b).
    if not re.search(r"createStatement|prepareStatement",
                     window + " " + match.group(0)):
        return False
    if not re.search(
            r"@RequestParam|@PathVariable|@RequestBody|@ModelAttribute"
            r"|getParameter\s*\(", window):
        return False
    # LAST assignment wins (WebGoat Lesson5a: `String query = "";` is
    # re-assigned the concatenated SQL before the sink -- checking only the
    # first assignment would treat the empty initializer as proof of a
    # literal query).
    assigns = list(re.finditer(
        r"\b" + re.escape(var) + r"\b\s*=\s*([^;]+);", window, re.S))
    if not assigns:
        return False
    rhs = assigns[-1].group(1)
    if not re.search(r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER\s+BY)",
                     rhs, re.I):
        return False
    # Concat with a non-literal operand: '+' followed by an identifier /
    # method call, not another string quote.
    return bool(re.search(r"\+\s*[A-Za-z_$]", rhs))


def _java_sql_prepared_concat(source: str, match: re.Match, language: str) -> bool:
    """WebGoat Assignment5/Servers shape: prepareStatement( with the concat
    spanning multiple lines INSIDE the call (batch-8's JAVA_JDBC_SQL_CONCAT
    is single-line). Requires a non-literal concat operand inside the balanced
    call region and request-parameter evidence in the window; literal-only
    queries and '?' placeholders stay dark.
    """
    if language != "java":
        return False
    region = _call_region(source, match.start(), cap=2000)
    if not region:
        return False
    if not re.search(r"\+\s*[A-Za-z_$]", region):
        return False
    lo = max(0, match.start() - 1500)
    window = source[lo:match.start()]
    return bool(re.search(
        r"@RequestParam|@PathVariable|@RequestBody|getParameter\s*\(", window))


def _php_sql_intermediate_query(source: str, match: re.Match, language: str) -> bool:
    """DVWA sqli/high.php shape: ``$query = \"SELECT ... '$id'\"`` then
    ``mysql_query($query)``. The sink argument must be a request-derived
    identifier whose assignment built a SQL string by interpolation or
    concatenation. Config-interpolated queries (DVWA includes/DBMS/MySQL.php:
    ``$drop_db = \"DROP DATABASE `{$_DVWA['db_database']}`\"``) carry no
    attacker control and stay dark -- adjudicated divergence from CNAP.
    """
    if language != "php":
        return False
    stmt = _php_statement(source, match)
    lo = max(0, match.start() - 1500)
    region = source[lo:match.start()]
    # Two hops: the php://input JSON body arrives as
    # `$json = file_get_contents('php://input'); $data = json_decode($json);`
    # and the query concatenates `$data->field` (DVWA
    # change_user_details.php:47-48) -- one pass tainted only `$json`.
    tainted = _php_tainted_vars(source, match.start(), passes=2)
    # The sink argument is a VARIABLE whose own assignment built the SQL
    # string from a request-derived part (direct superglobal, corpus-proven
    # session key, or a var one hop below one).
    for name in re.findall(r"\$([A-Za-z_]\w*)", stmt):
        m = re.search(r"\$" + re.escape(name) + r"\b\s*=\s*([^;\n]+)", region)
        if not m:
            continue
        rhs = m.group(1)
        if (not _php_direct_source_re().search(rhs)
                and not _php_tainted_in(rhs, tainted)):
            continue
        if not re.search(r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|DROP)",
                         rhs, re.I):
            continue
        # Non-literal part: '.'-concat with a variable, or a variable
        # interpolated inside a string literal.
        if (re.search(r"\.\s*\$", rhs)
                or re.search(r"[\"'][^\"']*\$\w+", rhs)):
            return True
    return False


def _php_xss_tainted_echo(source: str, match: re.Match, language: str) -> bool:
    """DVWA csp/jsonp.php shape: ``echo $callback . '(' . json_encode(..)``
    with ``$callback = $_GET['callback']`` (JSONP callback injection), plus
    direct interpolated echo. Safe wrappers (htmlspecialchars/json_encode/...)
    around the tainted occurrence suppress the finding; a value only one hop
    beyond request input (check_token_high.php ``print $ret``) stays dark.
    """
    if language != "php":
        return False
    stmt = _php_statement(source, match)
    stripped = _PHP_SAFE_WRAPPER_RE.sub("", stmt)
    if _PHP_REQUEST_SOURCE_RE.search(stripped):
        return True
    return _php_tainted_in(stripped, _php_tainted_vars(source, match.start(),
                                                      passes=1))


def _php_path_user_input_var(source: str, match: re.Match, language: str) -> bool:
    """DVWA view_source.php / view_source_all.php shape: $id/$security from
    GET interpolated into a file_get_contents path one hop below. basename()
    wrapping suppresses; whitelisted-map lookups (instructions.php, where a
    one-hop value is gated through array_key_exists against a fixed table)
    stay dark because propagation never leaves the direct assignment.

    php://input is deliberately NOT a direct path source: reading the request
    body via the fixed stream wrapper is the standard JSON API pattern (DVWA
    api/src/*Controller.php read it on every endpoint) and the PATH is a
    literal, not attacker-controlled. Body CONTENT reaching a path through a
    variable still counts, because there the path text is attacker-written.
    """
    if language != "php":
        return False
    stmt = _php_statement(source, match)
    if re.search(r"basename\s*\(", stmt):
        return False
    if re.search(
            r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
            r"|\$_SERVER\s*\[\s*[\"'](?:HTTP_|QUERY_STRING|REQUEST_URI)", stmt):
        return True
    return _php_tainted_in(stmt, _php_tainted_vars(source, match.start(),
                                                  passes=1))


def _php_session_id_predictable(source: str, match: re.Match, language: str) -> bool:
    """DVWA weak_id low/medium/high: session cookie value from time(), an
    $_SESSION counter, or md5(counter). Only session-named cookies qualify
    (dvwaSession/PHPSESSID/...); client-chosen non-session cookies
    (cookie-input.php 'id', pref.php 'lang') are a different family and stay
    dark. random_bytes/random_int/session_create_id values are quiet.
    """
    if language != "php":
        return False
    region = _call_region(source, match.start(), cap=800)
    if not region or len(region) < 3:
        return False
    name_m = re.search(r"[\"']([^\"']+)[\"']", region)
    if not name_m or not re.search(
            r"session|PHPSESSID|\bsid\b|sess", name_m.group(1), re.I):
        return False
    # Split the call's top-level args (quote/bracket aware) to isolate value.
    depth, quote, cur, parts = 0, None, [], []
    for ch in region[1:-1]:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    if len(parts) < 2:
        return False
    value = parts[1]
    if re.search(r"random_bytes|random_int|session_create_id", value, re.I):
        return False
    lo = max(0, match.start() - 1500)
    window = source[lo:match.start()]
    # The value is often a variable: resolve its own assignment RHS so
    # `$cookie_value = time(); setcookie("dvwaSession", $cookie_value)` and
    # `$cookie_value = md5($_SESSION[...]); setcookie(...)` are seen.
    value_rhs = ""
    for name in re.findall(r"\$([A-Za-z_]\w*)", value):
        m = re.search(r"\$" + re.escape(name) + r"\b\s*=\s*([^;\n]+)", window)
        if m:
            value_rhs = m.group(1)
            break
    predictable = lambda text: bool(re.search(
        r"(?:time|microtime|rand|mt_rand|uniqid)\s*\(", text))
    if predictable(value) or (value_rhs and predictable(value_rhs)):
        return True
    # Predictable only when an $_SESSION counter is being incremented in the
    # window and the value derives from $_SESSION (directly or through the
    # resolved assignment, e.g. md5 of the counter).
    if re.search(r"\+\+\s*\$_SESSION|\$_SESSION\s*\[[^\]]+\]\s*\+\+", window):
        if (re.search(r"\$_SESSION", value)
                or (value_rhs and re.search(r"\$_SESSION", value_rhs))
                or re.search(r"=\s*\$_SESSION", window)):
            return True
    return False


def _php_open_redirect_header(source: str, match: re.Match, language: str) -> bool:
    """DVWA open_redirect low/medium/high: header(\"location: \" . $_GET[...])
    (lowercase 'location:' included). Static targets and config-derived URLs
    stay dark (no request evidence in the statement or its direct vars)."""
    if language != "php":
        return False
    stmt = _php_statement(source, match)
    if _PHP_REQUEST_SOURCE_RE.search(stmt):
        return True
    return _php_tainted_in(stmt, _php_tainted_vars(source, match.start(),
                                                  passes=1))


def _php_cmd_injected_var(source: str, match: re.Match, language: str) -> bool:
    """DVWA exec medium/high + api/HealthController: shell_exec/exec fed a
    variable built from request input (2 hops: php://input json body counts).
    Guards keep the hardened impossible.php variant (ctype_digit-validated
    octets reassembled) and escapeshellarg/escapeshellcmd-wrapped arguments
    dark -- the blacklist-only str_replace chains in high/medium are
    bypassable and must fire.
    """
    if language != "php":
        return False
    stmt = _php_statement(source, match)
    if re.search(r"escapeshellarg\s*\(|escapeshellcmd\s*\(", stmt):
        return False
    lo = max(0, match.start() - 1500)
    window = source[lo:match.start()]
    if re.search(r"ctype_digit|ctype_alnum|is_numeric|intval\s*\("
                 r"|filter_var\s*\([^)]*FILTER_VALIDATE", window):
        return False
    return _php_tainted_in(stmt, _php_tainted_vars(source, match.start(),
                                                  passes=2))


def _express_csrf_missing(source: str, match: re.Match, language: str) -> bool:
    """Report a bare express() app only when it registers state-changing routes
    and installs no CSRF middleware anywhere in the file.

    A "missing control" posture indicator. Header-based (Authorization) APIs are
    CSRF-immune, so this is Medium confidence and fires only on the app file
    that actually wires post/put/patch/delete routes without any csrf/csurf
    reference — the shape adjudicated on juice-shop server.ts:130.
    """
    if language not in {"javascript", "typescript"}:
        return False
    # Must register at least one state-changing route in this file.
    if not re.search(r"\.\s*(?:post|put|patch|delete)\s*\(", source):
        return False
    # Any CSRF middleware reference means protection is present (or explicitly
    # configured) — do not report. csurf is spelled without the "csrf"
    # substring, so it is listed explicitly.
    if re.search(r"csrf|csurf|doublecsrf|xsrf", source, re.I):
        return False
    return True


def _jwt_decode_without_verify(source: str, match: re.Match, language: str) -> bool:
    """Report a jsonwebtoken decode() in a file that never calls verify().

    decode() returns the payload WITHOUT checking the signature, so trusting it
    for an auth decision is a bypass. The secure decode-then-verify pattern
    (juice-shop routes/verify.ts) calls verify() and is excluded. Bare decode()
    is only reported when the file actually imports/uses jsonwebtoken, so an
    unrelated base64/codec decode() is not a false positive.
    """
    if language not in {"javascript", "typescript"}:
        return False
    # Must be a jsonwebtoken context.
    if "jsonwebtoken" not in source:
        return False
    # Secure pattern: the file verifies signatures somewhere.
    if re.search(r"\bverify\s*\(", source):
        return False
    # Bare decode( must be the jsonwebtoken decode (named import or jwt.decode).
    if not re.search(r"jwt\s*\.\s*decode", match.group(0)):
        if not re.search(
            r"import\s*\{[^}]*\bdecode\b[^}]*\}\s*from\s*['\"]jsonwebtoken['\"]"
            r"|require\s*\(\s*['\"]jsonwebtoken['\"]\s*\)",
            source,
        ):
            return False
    return True


def _java_xpath_injection(source: str, match: re.Match, language: str) -> bool:
    """Report XPath-concatenation only in files that use the XPath API.

    The rule's literal already requires an XPath construct, but // also occurs
    in protocol-relative URLs, so the file must reference the XPath API to keep
    URL/HTML path building out of this rule's blast radius.
    """
    return bool(re.search(r"XPathFactory|newXPath|\bXPath\b", source))


# --- G23 coverage-audit gap-fix validators (2026-10-22) ---------------------
#
# Window/context guards for the non-Java gap rules added in ENTERPRISE_RULES.
# Each guard is a pure function of (source, match, language) wired into
# scan_file's dispatch: literals, escaped values, hardened parsers,
# ownership-checked handlers and validated extractions all stay dark.

_JS_DOM_SOURCE_RE = re.compile(
    r"(?:req|request)\s*\.\s*(?:query|params|body|headers)"
    r"|location\s*\.\s*(?:hash|search|href|pathname)"
    r"|document\s*\.\s*(?:URL|referrer|cookie|documentElement)"
    r"|window\s*\.\s*name"
    r"|localStorage|sessionStorage", re.I)

# Genuine HTML-context escapers. URL encoding (encodeURI) is deliberately NOT
# here: it does not stop HTML/JS injection.
_JS_XSS_ESCAPER_RE = re.compile(
    r"DOMPurify|escapeHtml|escapeHTML|htmlEscape|sanitize|_.escape"
    r"|he\.encode|textContent|createTextNode|encodeForHTML|bleach", re.I)


def _js_var_tainted(source: str, ident: str, pos: int) -> bool:
    """True when ``ident`` was assigned from a request/DOM source above ``pos``."""
    lo = max(0, pos - 1400)
    region = source[lo:pos]
    m = re.search(r"(?<![.\w$])" + re.escape(ident) + r"\s*=\s*([^;\n]+)", region)
    return bool(m and _JS_DOM_SOURCE_RE.search(m.group(1)))


def _js_dom_xss(source: str, match: re.Match, language: str) -> bool:
    """DOM sink fed a request/DOM-derived value. Literals and escaped values
    stay dark; a bare identifier is resolved one hop to its assignment."""
    if language not in {"javascript", "typescript"}:
        return False
    rhs = source[match.end():]
    m = re.search(r"[;\n]", rhs)
    rhs = rhs[: m.start()] if m else rhs[:300]
    if _JS_XSS_ESCAPER_RE.search(rhs):
        return False
    if _JS_DOM_SOURCE_RE.search(rhs):
        return True
    stripped = rhs.strip().rstrip(")")
    if re.fullmatch(r"[A-Za-z_$][\w$]*", stripped):
        return _js_var_tainted(source, stripped, match.start())
    return False


def _express_reflected_xss(source: str, match: re.Match, language: str) -> bool:
    """res.send/end/write reflecting req.query|params|body (raw HTML)."""
    if language not in {"javascript", "typescript"}:
        return False
    args = _call_region(source, match.start(), cap=500)
    if not args:
        return False
    if _JS_XSS_ESCAPER_RE.search(args):
        return False
    return bool(re.search(r"(?:req|request)\s*\.\s*(?:query|params|body)\b", args))


_CPP_FMT_INDEX = {
    "printf": 0, "vprintf": 0,
    "fprintf": 1, "vfprintf": 1,
    "sprintf": 1, "vsprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}


def _split_call_args(region: str) -> list:
    """Top-level (quote/bracket-aware) argument strings of a ``(...)`` region."""
    inner = region[1:-1] if region.startswith("(") else region
    parts, cur, depth, quote = [], [], 0, None
    for ch in inner:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts]


def _cpp_format_string(source: str, match: re.Match, language: str) -> bool:
    """printf-family call whose format-position argument is a variable (CWE-134)."""
    if language not in {"c", "cpp"}:
        return False
    func = match.groupdict().get("cfunc") or ""
    idx = _CPP_FMT_INDEX.get(func)
    if idx is None:
        return False
    region = _call_region(source, match.start(), cap=600)
    if not region:
        return False
    args = _split_call_args(region)
    if len(args) <= idx:
        return False
    return bool(re.fullmatch(r"[A-Za-z_]\w*", args[idx]))


def _cpp_use_after_free(source: str, match: re.Match, language: str) -> bool:
    """free(p) followed by p-> / p[ / p. / p++ within ~12 lines, with no
    intervening reassignment or NULL (the safe free-then-null pattern)."""
    if language not in {"c", "cpp"}:
        return False
    ptr = (match.groupdict() or {}).get("uaf_ptr") or ""
    if not ptr:
        return False
    esc = re.escape(ptr)
    after = source[match.end(): match.end() + 1400]
    for ln in after.splitlines()[:12]:
        if re.search(r"\b" + esc + r"\s*=\s*(?:NULL|nullptr|0|\w)", ln):
            return False
        if re.search(r"\b" + esc + r"\s*(?:->|\[|\.|\+\+|--)", ln):
            return True
    return False


_JS_REQUEST_ID_RE = re.compile(
    r"(?:req|request)\s*\.\s*(?:params|query|body)\b")
_PY_REQUEST_ID_RE = re.compile(
    r"request\.(?:GET|POST|PUT|PATCH|data|query_params|view_kwargs|args)\b")
# Ownership predicate tokens: an object owner/user comparison in the same
# function means the handler is not an open IDOR.
_JS_OWNERSHIP_RE = re.compile(
    r"userId|user_id|ownerId|owner_id|\bowner\b|createdBy|created_by"
    r"|(?:req|request)\s*\.\s*user\b|current_user|\.owner\b", re.I)
_PY_OWNERSHIP_RE = re.compile(
    r"request\.user|current_user|\bowner\b|created_by|user_id|userId|\.user\b", re.I)


def _js_function_body_span(source: str, pos: int):
    """(start,end) of the innermost brace block containing pos, else None."""
    depth = 0
    i = pos
    open_idx = -1
    while i > 0:
        i -= 1
        c = source[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                open_idx = i
                break
            depth -= 1
    if open_idx == -1:
        return None
    depth = 0
    j = open_idx
    while j < len(source):
        c = source[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return (open_idx, j + 1)
        j += 1
    return (open_idx, len(source))


def _py_def_body_span(source: str, pos: int):
    """(start,end) approximation of the python def-body enclosing pos."""
    defs = list(re.finditer(r"^[ \t]*def\s+\w+", source[:pos], re.M))
    if not defs:
        return None
    start = defs[-1].start()
    nxt = re.search(r"\n(?:[ \t]*def\s|[ \t]*class\s|[ \t]*@)", source[pos:])
    end = pos + nxt.start() if nxt else len(source)
    return (start, end)


def _idor_object_fetch(source, match, language, request_re, own_re) -> bool:
    """ORM fetch by a request-supplied id with NO ownership predicate in the
    enclosing function (the honest REST-IDOR sub-shape).

    Request evidence takes two shapes (G23 direct, G24 one hop):
      * the request expression inside the call window itself, or
      * one hop back: an identifier inside the fetch call is ASSIGNED from a
        request expression in the same handler body
        (oid = request.GET["id"]; ...objects.get(pk=oid)).  A fetch whose
        argument never receives request data (constant, config, whitelisted)
        stays dark, and the ownership gate is unchanged.
    """
    if language in {"javascript", "typescript"}:
        span = _js_function_body_span(source, match.start())
    else:
        span = _py_def_body_span(source, match.start())
    body = (source[span[0]:span[1]] if span
            else source[max(0, match.start() - 1500): match.start() + 1500])
    if own_re.search(body):
        return False
    region = _call_region(source, match.start(), cap=400)
    if region and request_re.search(region):
        return True
    return _fetch_arg_from_request(source, match, body, request_re)


_IDOR_ARG_ID_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\b")


def _fetch_arg_from_request(source, match, body, request_re) -> bool:
    """One hop back: some identifier inside the fetch call is assigned from a
    request expression in the same handler body."""
    paren = source.find("(", match.end() - 1)
    if paren == -1:
        return False
    depth = 0
    j = paren
    while j < len(source) and j - paren < 300:
        if source[j] == "(":
            depth += 1
        elif source[j] == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    args = source[paren + 1: j]
    for ident in {m.group(1) for m in _IDOR_ARG_ID_RE.finditer(args)}:
        assign = re.compile(
            r"\b(?:const|let|var)?\s*" + re.escape(ident)
            + r"\s*=\s*(?!=)" + request_re.pattern)
        if assign.search(body):
            return True
    return False


_PY_SESSION_ROTATE_RE = re.compile(
    r"session\s*\.\s*(?:clear|pop|regenerate|rotate)|cycle_key|"
    r"flush\s*\(\s*\)|session_identifier")


def _flask_session_fixation(source: str, match: re.Match, language: str) -> bool:
    """login_user() in a function that never rotates/clears the session id."""
    if language != "python":
        return False
    span = _py_def_body_span(source, match.start())
    body = (source[span[0]:span[1]] if span
            else source[max(0, match.start() - 800): match.start() + 800])
    return not _PY_SESSION_ROTATE_RE.search(body)


def _express_cookie_missing_secure(source: str, match: re.Match, language: str) -> bool:
    """res.cookie(...) call whose options lack secure: true."""
    if language not in {"javascript", "typescript"}:
        return False
    region = _call_region(source, match.start(), cap=800)
    if not region:
        return False
    return not re.search(r"secure\s*:\s*true", region, re.I)


# (langs, flag regex that must be present for the cookie to be safe).
# Go names the fields in a net/http.Cookie literal; .NET sets properties on
# a CookieOptions object. Both are structurally the same missing-option
# gate as the Express arm: the call region must carry the flag.
_COOKIE_FLAG_RULES = {
    "GO_COOKIE_MISSING_SECURE": ({"go"}, r"Secure\s*:\s*true"),
    "GO_COOKIE_MISSING_HTTPONLY": ({"go"}, r"HttpOnly\s*:\s*true"),
    "DOTNET_COOKIE_MISSING_SECURE": ({"csharp"}, r"Secure\s*=\s*true"),
    "DOTNET_COOKIE_MISSING_HTTPONLY": ({"csharp"}, r"HttpOnly\s*=\s*true"),
}


def _cookie_missing_flag(source: str, match: re.Match, language: str,
                         rule_id: str) -> bool:
    """A known cookie-setting call whose option block lacks the rule's flag."""
    langs, flag_re = _COOKIE_FLAG_RULES[rule_id]
    if language not in langs:
        return False
    region = _call_region(source, match.start(), cap=800)
    if not region:
        return False
    return not re.search(flag_re, region)


def _py_xml_entities(source: str, match: re.Match, language: str) -> bool:
    """lxml parse (entities resolved by default) with no hardening/defusedxml."""
    if language != "python":
        return False
    if "defusedxml" in source:
        return False
    if not re.search(r"\blxml\b", source):
        return False
    region = source[max(0, match.start() - 300): match.end() + 300]
    if re.search(
            r"resolve_entities\s*=\s*False|no_network\s*=\s*True"
            r"|load_dtd\s*=\s*False", region):
        return False
    return True


def _php_xxe_libxml(source: str, match: re.Match, language: str) -> bool:
    """simplexml/DOM load of request input, or an explicit entity-loader
    re-enable (libxml_disable_entity_loader(false))."""
    if language != "php":
        return False
    region = _call_region(source, match.start(), cap=400)
    if not region:
        return False
    if re.search(r"libxml_disable_entity_loader\s*\(\s*(?:false|0)\b", region):
        return True
    return bool(re.search(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|php://input", region))


def _has_nested_quantifier(pat: str) -> bool:
    """Conservative nested-quantifier / identical-alternation signature."""
    if re.search(r"\([^()]*[+*]\)\s*[+*+]", pat):
        return True
    if re.search(r"\((\w+)\|\1\)\s*[+*]", pat):
        return True
    return False


def _regex_literal_arg(region: str):
    m = re.search(r"[rRbBuUfF]{0,2}(['\"])(.*?)\1", region)
    return m.group(2) if m else None


def _py_redos(source: str, match: re.Match, language: str) -> bool:
    """re.* call whose regex literal carries a nested quantifier."""
    if language != "python":
        return False
    region = _call_region(source, match.start(), cap=300)
    if not region:
        return False
    lit = _regex_literal_arg(region)
    return bool(lit and _has_nested_quantifier(lit))


def _php_redos(source: str, match: re.Match, language: str) -> bool:
    """preg_* call whose pattern literal carries a nested quantifier."""
    if language != "php":
        return False
    region = _call_region(source, match.start(), cap=300)
    if not region:
        return False
    m = re.search(r"(['\"])(.*?)\1", region)
    return bool(m and _has_nested_quantifier(m.group(2)))


_HOST_URL_CONTEXT_RE = re.compile(
    r"https?://|mailto:|(?<![A-Za-z0-9_])mail\s*\(|\burl\b|Location\s*:", re.I)


def _host_header_injection(source: str, match: re.Match, language: str) -> bool:
    """Host header value used to build a URL/email (not merely displayed)."""
    window = source[max(0, match.start() - 400): match.end() + 400]
    return bool(_HOST_URL_CONTEXT_RE.search(window))


_WS_SINK_PARAM_RE = re.compile(
    r"\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>|function\s*\w*\s*\(\s*([A-Za-z_$][\w$]*)")
_WS_SINK_RE = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\.\s*innerHTML\s*=|child_process"
    r"|\.exec(?:Sync)?\s*\(|\bdb\w*\s*\.\s*(?:query|run|exec)\s*\(")


def _node_websocket_sink(source: str, match: re.Match, language: str) -> bool:
    """WebSocket 'message'/'data' handler whose payload reaches a dangerous sink."""
    if language not in {"javascript", "typescript"}:
        return False
    region = _call_region(source, match.start(), cap=1000)
    if not region or not _WS_SINK_RE.search(region):
        return False
    pm = _WS_SINK_PARAM_RE.search(region)
    param = (pm.group(1) or pm.group(2)) if pm else None
    if not param:
        return True
    esc = re.escape(param)
    return bool(re.search(
        r"\beval\s*\(\s*" + esc + r"\b"
        r"|\bnew\s+Function\s*\(\s*" + esc + r"\b"
        r"|\.\s*innerHTML\s*=\s*[^\n;]*" + esc + r"\b"
        r"|\.exec(?:Sync)?\s*\(\s*[^\n;]*" + esc + r"\b"
        r"|\bdb\w*\s*\.\s*(?:query|run|exec)\s*\(\s*[^\n;]*" + esc + r"\b",
        region))


def _py_tar_extractall(source: str, match: re.Match, language: str) -> bool:
    """tarfile extractall with no member validation in the surrounding window.

    The regex anchors on ``.extractall`` so the finding sits on the call line;
    this guard restricts it to tarfile (zipfile.extractall is already claimed
    by the pre-existing GENERIC_ZIPSLIP rule) and requires no member check.
    """
    if language != "python":
        return False
    pre = source[max(0, match.start() - 250): match.start()]
    if not re.search(r"\btarfile\b", pre):
        return False
    window = source[max(0, match.start() - 300): match.end() + 300]
    if re.search(
            r"data_filter|extraction_filter|getmembers|namelist"
            r"|commonpath|is_within", window, re.I):
        return False
    return True



def _is_tenant_isolation_candidate(
    source: str,
    match: re.Match,
    language: str,
    filepath: str,
) -> bool:
    """Require a server-side object/data-access context before flagging tenant IDs.

    A tenantId/organizationId declaration by itself is not a security finding.
    This gate requires a server-side route/controller context plus an object/data
    access operation in the same local region. Browser/UI state, React context,
    client navigation and plain configuration are therefore excluded.
    """
    path = str(filepath or "").replace("\\", "/").lower()

    # Explicitly reject obvious browser/UI/client-side contexts.
    if any(marker in path for marker in (
        "/frontend/", "/client/", "/web/", "/src/components/",
        "/src/context/", "/src/pages/", "/src/hooks/",
    )):
        return False

    start = max(0, match.start() - 900)
    end = min(len(source), match.end() + 1400)
    ctx = source[start:end]

    # Require a server-side route/controller/handler signal.
    route_patterns = {
        "python": r'@(?:app|router|api|bp)\.(?:route|get|post|put|patch|delete|api_route)\s*\(|(?:path|re_path)\s*\(',
        "javascript": r'\b(?:app|router|api|server)\s*\.\s*(?:get|post|put|patch|delete|all|use|route)\s*\(',
        "typescript": r'\b(?:app|router|api|server)\s*\.\s*(?:get|post|put|patch|delete|all|use|route)\s*\(',
        "java": r'@(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(',
        "csharp": r'\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route)\b',
        "go": r'http\.(?:HandleFunc|Handle)\s*\(|\b(?:mux|router|chi|gin|echo)\s*\.\s*(?:Handle|HandleFunc|Get|Post|Put|Patch|Delete|Any)\s*\(',
        "php": r'\bRoute\s*::\s*(?:get|post|put|patch|delete|match|any)\s*\(|#\[\s*Route\s*\(',
    }
    route_pat = route_patterns.get(language)
    if not route_pat or not re.search(route_pat, ctx, re.I | re.M):
        return False

    # Require actual object/data access, not merely a tenant field declaration.
    access_pat = (
        r'\b(?:findById|findOne|getById|findByPk|repository|repo\.|'
        r'db\.|execute|query|select|Model\.find|EntityManager|'
        r'getRepository|objects\.get|objects\.filter|prisma\.\w+)\b'
    )
    if not re.search(access_pat, ctx, re.I):
        return False

    return True


def _remediation(
    vuln: str,
    mapping: dict,
    custom: list[str] | None = None,
    rule_id: str | None = None,
    language: str | None = None,
) -> list[str]:
    # Keep rule identity and language separate for semantic callers.
    if custom:
        return custom
    lang = (language or "").lower()
    if vuln == "insecure_deserialization" and lang in {"javascript", "typescript"} and (
        "jsyaml" in str(mapping).lower() or "js-yaml" in str(mapping).lower() or "yaml" in str(mapping).lower()
    ):
        return [
            "Upgrade js-yaml to a supported, non-vulnerable version and review the package lockfile for the resolved version.",
            "Parse uploaded/untrusted YAML with the safe schema/options appropriate to the installed js-yaml version; do not enable unsafe JavaScript object construction or custom tags unless explicitly required.",
            "Validate the parsed object against an expected schema before using it in application logic or filesystem/network operations.",
            "Add regression tests containing malicious YAML tags, unexpected object types, oversized documents, and representative untrusted upload payloads.",
        ]
    if vuln == "ssrf":
        return [
            "Allow outbound requests only to an explicit server-side destination allow-list; never trust a client-supplied URL by itself.",
            "Resolve the destination and validate every resulting IP address, including IPv4, IPv6, loopback, link-local, private, and cloud-metadata ranges.",
            "Re-validate the destination after DNS resolution and after redirects; prevent DNS-rebinding and redirect-based allow-list bypasses.",
            "Allow only required URL schemes, use a controlled egress proxy where possible, and block direct access to internal management and metadata endpoints.",
            "Add regression tests for private IPs, IPv6, encoded/alternate IP forms, redirects, DNS rebinding, and cloud metadata addresses.",
        ]
    if vuln == "nosql_injection":
        return [
            "If the flagged query input is attacker-controlled, replace dynamically constructed query expressions with structured field/value queries.",
            "Allow-list accepted fields and operators; reject unexpected query operators such as $where or $regex when they are not required.",
            "Do not pass request objects directly into database query filters; construct the filter from validated scalar values.",
            "Add negative tests for operator injection, object-shaped parameters, regex abuse, and unexpected query fields.",
        ]
    # V17.9.14 semantic contract: preserve rule-specific remediation even
    # when the caller does not provide a mapper entry.
    if str(rule_id or "").upper() == "SUPPLY_CHAIN_SCRIPT" or vuln == "supply_chain_script":
        return [
            "Enforce a committed package-lock.json (or equivalent lockfile) and review lockfile changes during code review.",
            "Use npm ci in controlled CI/CD rather than npm install so dependency resolution is reproducible.",
            "Review lifecycle scripts (preinstall/install/postinstall) and use --ignore-scripts where lifecycle execution is not required.",
            "Pin dependency versions and verify package provenance/integrity; regenerate the SBOM after dependency changes.",
            "Add CI regression checks for unexpected dependency or lifecycle-script changes.",
        ]
    if str(rule_id or "").upper() == "MD5_USAGE" or vuln in {"weak_crypto", "md5_usage"}:
        return [
            "Replace MD5 with SHA-256 or a stronger modern hash when hashing is required for integrity or non-password data.",
            "For password storage, use a dedicated password-hashing scheme such as Argon2id or bcrypt with an appropriate work factor.",
            "Do not use MD5 for authentication, password storage, signatures, or security-sensitive integrity decisions.",
            "Add regression tests verifying the selected algorithm and rejecting legacy MD5 usage in security-sensitive code paths.",
        ]
    if vuln == "path_traversal" and lang in {"javascript", "typescript"}:
        return [
            "Resolve the requested filename against a fixed base directory using path.resolve(). Keep the resolved path inside the fixed base directory.",
            "Verify path.relative(baseDir, resolvedPath) does not escape the base directory; reject absolute paths and traversal segments.",
            "Prefer server-generated file IDs instead of accepting raw filesystem paths from clients.",
            "Add tests for ../, encoded traversal, absolute paths, and Windows-style traversal inputs.",
        ]
    if vuln == "code_injection" and lang in {"javascript", "typescript"}:
        return [
            "Remove eval(), new Function(), vm.runIn*(), or equivalent dynamic execution from request-controlled paths.",
            "Use JSON.parse() or a schema validator for data; do not turn input strings into executable JavaScript.",
            "If dynamic behavior is unavoidable, allow-list the supported operations and map them to fixed functions.",
            "Add regression tests proving crafted expressions are rejected and cannot execute code.",
        ]
    m = mapping.get("remediation") if isinstance(mapping, dict) else None
    if isinstance(m, list) and m:
        return m
    return BASE_REMEDIATION.get(vuln, ["Validate all user-controlled input at trust boundaries.", "Use safe framework APIs and least privilege.", "Add unit tests and security regression tests for this pattern."])


def _make_finding(rule: dict, filepath: str, lineno: int, snippet: str, language: str) -> dict:
    vuln = rule.get("vuln_type") or rule.get("vuln") or "enterprise_control"
    mapping = get_mapping(vuln)
    fallback_controls = BIG4_CONTROL_FALLBACKS.get(vuln, {})
    title = rule.get("name") or rule.get("title") or rule.get("id") or vuln
    sev = rule.get("severity") or rule.get("sev") or mapping.get("severity", "Medium")
    cwe = rule.get("cwe") or mapping.get("cwe", "")
    owasp = rule.get("owasp") or mapping.get("owasp", "")
    rule_id = rule.get("id") or re.sub(r"[^A-Z0-9]+", "_", title.upper()).strip("_")
    confidence = "High" if sev == "Critical" else rule.get("confidence", "Medium")
    return {
        "rule_id": rule_id,
        "title": title,
        "vuln_type": vuln,
        "severity": sev,
        "priority": _priority(sev),
        "confidence": confidence,
        "language": language,
        "file": filepath,
        "line": lineno,
        "snippet": snippet,
        "description": rule.get("note") or rule.get("description") or f"Enterprise static control matched: {title}.",
        "remediation": _remediation(
            vuln,
            mapping,
            rule.get("remediation"),
            rule.get("id") or rule.get("rule_id"),
            language,
        ),
        "owasp": owasp,
        "owasp_id": mapping.get("owasp_id", ""),
        "cwe": cwe,
        "cwe_desc": mapping.get("cwe_desc", ""),
        "mitre": mapping.get("mitre", ""),
        "mitre_desc": mapping.get("mitre_desc", ""),
        "pci_dss": mapping.get("pci_dss") or fallback_controls.get("pci_dss", ""),
        "nist": mapping.get("nist") or fallback_controls.get("nist", ""),
        "iso27001": mapping.get("iso27001") or fallback_controls.get("iso27001", ""),
        "iso_27001": mapping.get("iso_27001") or mapping.get("iso27001") or fallback_controls.get("iso27001", ""),
        "nist_800_53": mapping.get("nist_800_53") or mapping.get("nist") or fallback_controls.get("nist", ""),
        "soc2": mapping.get("soc2") or fallback_controls.get("soc2", ""),
        "business_impact": mapping.get("business_impact", ""),
        "exploitability": "High" if sev in {"Critical", "High"} else "Medium",
        "evidence": f"{filepath}:{lineno}: {snippet}",
        "data_flow": "",
        "taint_path": "",
        "detection": rule.get("detection", "Enterprise SAST Pattern"),
        "engine": "scanner.sast",
        "cvss": None,
        "cve": None,
        "cve_note": "Code-level vulnerability (no CVE).",
        "group_key": f"{rule_id}|{filepath}|{lineno}|{snippet[:120]}",
        "enterprise_control": True,
    }


# ---- G-037: a shell sink is not, by itself, evidence ----------------------
# SUBPROCESS_SHELL_TRUE and OS_SYSTEM are pure sink-presence regexes: they
# fire on the existence of the call and never on anything reaching it. On the
# AI/LLM corpus that produced 11 findings and 3 violated negative controls,
# every one carrying no source at all - `engine` came from
# detect_container_engine() iterating the fixed list ["docker","podman"],
# CONTAINER_NAME was a module constant, and `cmd` was a bare parameter of a
# generic CLI runner.
#
# Both rules only match Python-shaped sinks (`subprocess.*(shell=True)`,
# `os.system(`), and the taint engine parses Python with ast. It models
# sources, interprocedural constant propagation and the argv no-shell case,
# so it is the arbiter: keep the regex finding only when the taint engine
# independently reported a command-injection path at that same sink. When a
# real source does reach `os.system(...)`, the taint engine reports it and the
# regex finding survives alongside it - this gate removes nothing that was
# ever shown to be reachable.
SHELL_SINK_RULE_IDS = frozenset({"SUBPROCESS_SHELL_TRUE", "OS_SYSTEM"})
SHELL_SINK_TAINT_WINDOW = 3

# Literal right-hand sides that are toggles and sentinels rather than secrets.
# Deliberately does NOT contain "bar" or "foobar": in this codebase both are
# the enforced API key that returns 401, so excluding them would suppress a
# real authorization gate because it looks like a placeholder.
_CREDENTIAL_PLACEHOLDER_VALUES = frozenset({
    "", "none", "null", "nil", "undefined", "true", "false", "default",
    "changeme", "example", "sample", "dummy", "placeholder", "todo", "fixme",
    "xxx", "redacted", "test", "testing", "unset",
})

# A literal whose ENTIRE value is a placeholder stem plus, at most, a
# credential-noun decoration: "some_key", "custom_key", "fakekey",
# "demo_token", "test-key", "fake-api-key", "your_api_key", "overwrite-key".
# Anchored at BOTH ends, so "some_key_prod_9x2" (which could hold material)
# and the real word "customer_key" are untouched, and the deliberately-real
# "bar"/"foobar" sentinels stay reportable.
_PLACEHOLDER_VALUE_PREFIX = re.compile(
    r"(?i)^(?:some|custom|fake|sample|dummy|demo|placeholder|changeme|example"
    r"|test|testing|unit|unittest|mock|your|overwrite|replaceme|temp|temporary|new)"
    r"[_-]?(?:api[_-]?(?:key|token|secret)|access[_-]?(?:key|token)"
    r"|private[_-]?key|client[_-]?secret|auth[_-]?(?:key|token|secret)"
    r"|key|keys|token|secret|pass|password|passwd|pwd|cred|credential|"
    r"value|val|data|thing|name)?$"
    # "sk-password" / "sk-test" -- the sk- vendor prefix followed by a
    # dictionary word can only be a stand-in; real sk- keys carry 20+ random
    # characters after the prefix and never fullmatch this alternative.
    r"|^sk[-_](?:api[_-]?key|key|secret|password|passwd|pwd|token|test|placeholder|fake|dummy|xxxx+)$"
)
# CamelCase stand-ins whose stems the alternation above cannot reach once the
# value is lowercased: "testAppClientSecret" (CopilotStudioTests.cs).  The
# stem must END where an uppercase letter begins.
_CAMEL_PLACEHOLDER_PREFIX = re.compile(
    r"^(?:[Tt]est|[Mm]ock|[Ff]ake|[Dd]ummy|[Ss]ample|[Dd]emo|[Yy]our|[Ee]xample)(?:[A-Z_])"
)


def _is_placeholder_credential(match: "re.Match[str]") -> bool:
    """True when the compared literal is a sentinel, not secret material."""
    try:
        raw_value = (match.group("credval") or "").strip()
    except (IndexError, re.error):
        return False
    if raw_value.startswith("/") and re.fullmatch(r"/[\w./-]+", raw_value):
        # A URL/path constant (e.g. "/faces/pages/login.xhtml"), not secret material.
        return True
    if _ENV_VAR_NAME_VALUE.fullmatch(raw_value):
        # "AZURE_COGNITIVE_SEARCH_ADMIN_KEY" names an environment variable:
        # a SCREAMING_SNAKE NAME at a credential key is a reference, not
        # material (SK utils.py ENV_VAR_API_KEY). Single-token caps values
        # ("SUP3RSECRET123") do not match and stay reportable.
        return True
    value = raw_value.lower()
    if value in _CREDENTIAL_PLACEHOLDER_VALUES:
        return True
    if _PLACEHOLDER_VALUE_PREFIX.fullmatch(value):
        # "some_key" / "custom_key" in test fixtures: obvious stand-ins, and
        # every real occurrence of these stems in scan corpora was one.
        return True
    return bool(re.fullmatch(r"<[^>]+>|\{[^}]*\}|%[sdf]", value))


# The ungated string-literal pattern matched ANY C# declaration of 8+
# characters ("var model = \"meta-llama-3-8b-instruct\"", "var prompt =
# \"Hello, world!\"") and produced 1327 rows on semantic-kernel and 199 on
# autogen -- 93% of which were model names, prompts and test fixtures. The
# declaration's IDENTIFIER must name a credential for the literal to be one.
_DOTNET_CREDENTIAL_IDENTIFIER = re.compile(
    r"(?i)(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|credential"
    r"|connection[_-]?(?:string|str)|conn[_-]?(?:string|str)"
    r"|auth(?:entication)?[_-]?(?:key|token|secret)"
    r"|private[_-]?key|client[_-]?secret|access[_-]?key"
    r"|sas(?:[_-]?token)?|signing[_-]?(?:key|secret))"
)
# A declaration's VALUE that only NAMES something is not material: the OTel
# constants ``const string MaxToken = "gen_ai.request.max_tokens"`` (a dotted
# attribute name, the C# twins of the python SOURCE rows) and
# ``ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY"`` (a SCREAMING_SNAKE
# environment-variable name) are references, not secrets. Mixed-case literals
# (``"Sup3rSecretValue!42"``) and single-token caps values (``"SUP3RSECRET123"``)
# stay reportable -- the env-name form demands >=2 underscore word breaks.
_DOTNET_VALUE_NAME = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")
_ENV_VAR_NAME_VALUE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){2,}$")

_TEST_PATH_PARTS = frozenset(
    {"test", "tests", "unittest", "unittests", "spec", "specs", "__tests__", "testing"}
)


def _looks_like_test_path(filepath) -> bool:
    """True for test-suite paths whose fixtures are deliberate stand-ins."""
    p = str(filepath).replace("\\", "/").lower()
    parts = set(seg for seg in p.split("/") if seg)
    name = p.rsplit("/", 1)[-1]
    return bool(parts & _TEST_PATH_PARTS) or name.startswith("test_") \
        or name.endswith("_test.py") or ".tests." in name


def _gate_shell_sink_findings(results: list[dict]) -> list[dict]:
    """Drop shell-sink regex findings that no taint path corroborates.

    Deliberately fail-open on anything not positively reasoned about: only the
    two shell-sink rule ids are ever removed, and only when the taint engine
    ran successfully for the same file. An engine that reported nothing must
    not be reachable here as "proof of absence" - the caller guards that.
    """
    taint_lines = {
        int(f.get("line") or 0)
        for f in results
        if isinstance(f, dict)
        and str(f.get("vuln_type") or "") == "command_injection"
        and str(f.get("rule_id") or "") not in SHELL_SINK_RULE_IDS
    }

    kept: list[dict] = []
    for finding in results:
        if not isinstance(finding, dict) or \
                str(finding.get("rule_id") or "") not in SHELL_SINK_RULE_IDS:
            kept.append(finding)
            continue
        line = int(finding.get("line") or 0)
        if any(abs(line - t) <= SHELL_SINK_TAINT_WINDOW for t in taint_lines):
            kept.append(finding)
        # Otherwise the sink was never shown to carry an untrusted value, so
        # it is not reported.  T-0.1: "not reported" must still be an
        # explained decision, not a silent disappearance.
        else:
            filter_trace.record_finding_drop(
                finding, "shell_sink_taint_gate",
                f"shell-sink regex hit (line {line}) has no taint-validated "
                f"command_injection occurrence within ±"
                f"{SHELL_SINK_TAINT_WINDOW} lines")
    return kept


# C1 (2026-10-16, llama_index): a code-EXECUTION classification requires
# executable-code context.  JSON is a pure data-interchange format -- it
# is never interpreted as code -- and nearly every character of a JSON
# file sits inside a string value, so the Python/JavaScript
# string-context helpers cannot apply.  The report fired EVAL_CALL
# twice on ``eval(`` occurring inside the ``"content"`` string of two
# Discord chat-log dumps (docs/examples/.../help_channel_dump_*.json
# line 74901) -- a user quoting a Python traceback.  Only the
# code_injection class is gated; secrets, crypto, SSRF and every other
# rule keep scanning JSON unchanged (the json secret/command-injection
# controls pin that).
NON_EXECUTABLE_DATA_LANGUAGES = frozenset({"json"})


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)
    # Third-party scanner-result XML exports are tool output, not source.
    # Checked BEFORE the read so a 64 MB findsecbugs/ZAP export is never even
    # loaded into memory.
    if _is_scanner_result_xml(path):
        return []
    # T-0.2: shared content read through the scan's index -- one disk read
    # per file per scan even though sast, taint and every BOM engine all
    # need the text. Falls back to a direct read when no scan is active.
    source = file_index.read_source(path)
    if source is None:
        return []
    lines = source.splitlines()
    language = _language(path)
    findings: list[dict] = []

    # package-lock.json records resolved dependency versions; it is not the
    # authoritative source for npm lifecycle scripts or unpinned declarations.
    # Those controls must be evaluated from package.json only.
    package_lock = path.name.lower() == "package-lock.json"

    # Generated/report artifacts are not executable application source.
    if _skip(path):
        return []

    # Existing rules
    for rule in REGEX_RULES:
        allowed = rule.get("languages") or rule.get("lang")
        if allowed and language not in allowed:
            continue
        if (rule.get("vuln_type") == "code_injection"
                and language in NON_EXECUTABLE_DATA_LANGUAGES):
            # C1: eval()/exec() semantics cannot occur in a data file;
            # see NON_EXECUTABLE_DATA_LANGUAGES above.
            continue
        for match in regex_budget.timed_finditer(
                rule["pattern"], source,
                rule_id=rule.get("id") or "?",
                file_path=str(filepath)):
            if (
                _match_starts_in_comment(source, match.start(), language)
                or _match_starts_in_python_string(source, match.start(), language)
                or _match_starts_in_javascript_string(source, match.start(), language)
                or _match_starts_in_javascript_comment(source, match.start(), language)
            ):
                continue
            lineno, snippet = _snippet_for_match(rule, source, lines, match.start(), match.end())
            if _is_comment(snippet, language):
                continue
            if rule.get("id") in {"HARDCODED_CREDENTIAL_COMPARISON",
                                  "GENERIC_API_KEY_PASSWORD"} and _is_placeholder_credential(match):
                continue
            if (rule.get("id") == "HARDCODED_CREDENTIAL_COMPARISON"
                    and match.group("credval").upper() in _HTTP_METHOD_VERBS):
                continue
            if (rule.get("id") in {"MD5_USAGE", "SHA1_USAGE"}
                    and not _aliased_hashlib_match(source, match, rule, language)):
                # 2026-10-21 prodtest/pygoat: the bare md5(/sha1( arm is the
                # hashlib API only when the file imports that name from
                # hashlib; a local helper with the same name is not crypto.
                continue
            if rule.get("id") == "PRIVATE_KEY_HEADER":
                # G4 (2026-10-19, prodtest): the header marker alone is not
                # key material. WebGoat CryptoUtil.java:49/137 builds/strips
                # PEM headers as string literals and wrongsecrets
                # Challenge29.java:59 strips them from a runtime-loaded file
                # -- none contains a private key. The rule's claim ("Private
                # key material in source code") requires a base64 key body
                # between the header and the next END marker (or within 1200
                # chars when the block is truncated); real embedded key
                # blocks -- raw multi-line PEMs and single-string Java
                # literals -- carry that body and keep their finding.
                _pem_after = source[match.end():match.end() + 1200]
                _pem_end = re.search(r"-----END", _pem_after)
                _pem_region = _pem_after[:_pem_end.start()] if _pem_end else _pem_after
                if not re.search(r"[A-Za-z0-9+/]{48,}={0,2}", _pem_region):
                    continue
            findings.append(_make_finding(rule, filepath, lineno, snippet, language))

    # Enterprise controls. Apply only to relevant languages to avoid noise.
    for rule in COMPILED_ENTERPRISE_RULES:
        langs = rule.get("langs") or []
        if langs and language not in langs:
            # config files sometimes have language yaml/properties/json but path matters
            if not (language in {"yaml", "properties", "json", "xml", "graphql"} and any(l in langs for l in [language])):
                continue
        for match in regex_budget.timed_finditer(
                rule["pattern"], source,
                rule_id=rule.get("id") or "?",
                file_path=str(filepath)):
            if rule.get("id") == "NPM_SUPPLY_CHAIN_SCRIPT" and package_lock:
                continue
            if str(rule.get("vuln") or rule.get("vuln_type") or "").lower() == "ssrf":
                # Do not report browser-side/client-side requests as SSRF.
                # SSRF requires a server-side outbound request sink.
                match_line_start = source.rfind("\n", 0, match.start()) + 1
                match_line_end = source.find("\n", match.end())
                if match_line_end == -1:
                    match_line_end = len(source)
                match_line = source[match_line_start:match_line_end]
                if _is_client_side_ssrf_context(filepath, match_line):
                    continue
                # Configured service endpoints are outbound dependencies, not
                # user-controlled SSRF sources. Require a request-derived value.
                if re.search(r"(?:process\.env|llmApiUrl|baseUrl|serviceUrl|configuredUrl)", match_line, re.I) and not re.search(
                    r"(?:req\.|request\.|body\b|query\b|params\b|_GET|_POST)", match_line, re.I
                ):
                    continue

            if rule.get("id") == "MISSING_RATE_LIMIT_ENDPOINT":
                if not _is_rate_limit_endpoint_match(source, match, language):
                    continue
                if _rate_limit_present(source, match):
                    continue

            if rule.get("id") == "EXPRESS_CSRF_MISSING":
                if not _express_csrf_missing(source, match, language):
                    continue

            if rule.get("id") in _PY_COOKIE_FLAG_BY_RULE:
                if not _py_cookie_flag_missing(
                    source, match, language, _PY_COOKIE_FLAG_BY_RULE[rule["id"]]
                ):
                    continue

            if rule.get("id") in _PHP_COOKIE_FLAG_BY_RULE:
                if not _php_cookie_flag_missing(
                    source, match, language, _PHP_COOKIE_FLAG_BY_RULE[rule["id"]][0]
                ):
                    continue

            if rule.get("id") == "JAVA_CIPHER_CBC_STATIC_IV":
                if not _java_cbc_static_iv(source, match, language):
                    continue

            # --- batch 10 (2026-10-21): intermediate-variable sinks -------
            # PHP position guard first: a keyword-sink pattern can start
            # inside a string (DVWA csp: $_POST['include'] -- 'include' is a
            # parameter NAME, not a sink). Anchored rules never match in
            # string content, so this is a pure FP guard.
            if rule.get("id") in _BATCH10_PHP_RULE_IDS and _match_starts_in_php_string(
                    source, match.start(), language):
                continue

            if rule.get("id") == "JAVA_JDBC_SQL_INTERMEDIATE_QUERY":
                if not _java_sql_intermediate_query(source, match, language):
                    continue

            if rule.get("id") == "JAVA_JDBC_SQL_PREPARED_CONCAT":
                if not _java_sql_prepared_concat(source, match, language):
                    continue

            if rule.get("id") == "PHP_SQL_INTERMEDIATE_QUERY":
                if not _php_sql_intermediate_query(source, match, language):
                    continue

            if rule.get("id") == "PHP_XSS_TAINTED_ECHO":
                if not _php_xss_tainted_echo(source, match, language):
                    continue

            if rule.get("id") == "PHP_PATH_USER_INPUT_VAR":
                if not _php_path_user_input_var(source, match, language):
                    continue

            if rule.get("id") == "PHP_SESSION_ID_PREDICTABLE":
                if not _php_session_id_predictable(source, match, language):
                    continue

            if rule.get("id") == "PHP_OPEN_REDIRECT_HEADER":
                if not _php_open_redirect_header(source, match, language):
                    continue

            if rule.get("id") == "PHP_CMD_INJECTION_INTERMEDIATE":
                if not _php_cmd_injected_var(source, match, language):
                    continue

            if rule.get("id") == "EXPRESS_SESSION_COOKIE_NO_EXPIRY":
                if not _express_session_no_expiry(source, match, language):
                    continue

            if rule.get("id") == "NODE_JWT_DECODE_NO_VERIFY":
                if not _jwt_decode_without_verify(source, match, language):
                    continue

            # --- G23 coverage-audit gap-fix validators (2026-10-22) -------
            if rule.get("id") == "NODE_DOM_XSS":
                if not _js_dom_xss(source, match, language):
                    continue

            if rule.get("id") == "EXPRESS_REFLECTED_XSS":
                if not _express_reflected_xss(source, match, language):
                    continue

            if rule.get("id") == "CPP_FORMAT_STRING":
                if not _cpp_format_string(source, match, language):
                    continue

            if rule.get("id") == "CPP_USE_AFTER_FREE":
                if not _cpp_use_after_free(source, match, language):
                    continue

            if rule.get("id") == "NODE_IDOR_OBJECT_FETCH":
                if not _idor_object_fetch(
                        source, match, language, _JS_REQUEST_ID_RE, _JS_OWNERSHIP_RE):
                    continue

            if rule.get("id") == "PY_IDOR_OBJECT_FETCH":
                if not _idor_object_fetch(
                        source, match, language, _PY_REQUEST_ID_RE, _PY_OWNERSHIP_RE):
                    continue

            if rule.get("id") == "FLASK_SESSION_FIXATION":
                if not _flask_session_fixation(source, match, language):
                    continue

            if rule.get("id") == "EXPRESS_COOKIE_MISSING_SECURE":
                if not _express_cookie_missing_secure(source, match, language):
                    continue

            if rule.get("id") in _COOKIE_FLAG_RULES:
                if not _cookie_missing_flag(source, match, language,
                                            rule.get("id")):
                    continue

            if rule.get("id") == "PY_XML_ENTITIES":
                if not _py_xml_entities(source, match, language):
                    continue

            if rule.get("id") == "PHP_XXE_LIBXML":
                if not _php_xxe_libxml(source, match, language):
                    continue

            if rule.get("id") == "PY_REDOS_NESTED_QUANTIFIER":
                if not _py_redos(source, match, language):
                    continue

            if rule.get("id") == "PHP_REDOS_NESTED_QUANTIFIER":
                if not _php_redos(source, match, language):
                    continue

            if rule.get("id") == "HOST_HEADER_INJECTION":
                if not _host_header_injection(source, match, language):
                    continue

            if rule.get("id") == "NODE_WEBSOCKET_SINK":
                if not _node_websocket_sink(source, match, language):
                    continue

            if rule.get("id") == "PY_TAR_EXTRACTALL":
                if not _py_tar_extractall(source, match, language):
                    continue

            if rule.get("id") == "JAVA_XPATH_INJECTION":
                if not _java_xpath_injection(source, match, language):
                    continue

            if rule.get("id") == "TENANT_ISOLATION_MISSING":
                if not _is_tenant_isolation_candidate(source, match, language, filepath):
                    continue

            if rule.get("id") == "DOTNET_HARDCODED_CREDENTIAL":
                # Kill-only identifier gate: only credential-named
                # declarations are hardcoded credentials. Model names,
                # deployment names, prompts and question strings are not.
                _ident = (match.group("ident") or "") if "ident" in match.groupdict() else ""
                if not _ident or not _DOTNET_CREDENTIAL_IDENTIFIER.search(_ident):
                    continue
                # Value-side name gate: a credential-named declaration whose
                # literal only NAMES something (OTel dotted attribute names,
                # SCREAMING_SNAKE env-var names) is a reference, not material.
                _lit = re.search(r'"([^"]{8,})"', match.group(0))
                if _lit:
                    _val = _lit.group(1)
                    if _ENV_VAR_NAME_VALUE.fullmatch(_val) or (
                        _DOTNET_VALUE_NAME.fullmatch(_val)
                        and all(len(seg) <= 24 for seg in _val.split("."))
                    ):
                        continue

            if rule.get("id") == "WORKFLOW_APPROVAL_BYPASS":
                _wf_start = source.rfind("\n", 0, match.start()) + 1
                _wf_end = source.find("\n", match.end())
                _wf_line = source[_wf_start: len(source) if _wf_end == -1 else _wf_end]
                if _looks_like_test_path(filepath):
                    # Approval handlers and mocks in test suites
                    # (ApprovalResponse(approved=True, ...)) exercise the
                    # control, they do not bypass it.
                    continue
                if re.search(r"(?i)auto[_-]?approve[^\n]*?\bfalse\b", _wf_line):
                    # Secure default: auto-approve disabled
                    # (``sampling_auto_approve: bool = False``).
                    continue
                if re.search(r"(?i)auto[_-]?approve\s*[:=]\s*(?!true\b|false\b)[A-Za-z_][\w.]*\s*$", _wf_line):
                    # Identifier passthrough (``self.x = x``), not an
                    # enabled value. Booleans are excluded: ``= True`` is
                    # an enabled bypass and must keep reporting.
                    continue

            # Reject matches that begin inside a real comment. This is
            # position-aware and therefore works for multiline regex rules.
            if (
                _match_starts_in_comment(source, match.start(), language)
                or _match_starts_in_python_string(source, match.start(), language)
                or _match_starts_in_javascript_string(source, match.start(), language)
                or _match_starts_in_javascript_comment(source, match.start(), language)
            ):
                continue

            # A fixed Function(specifier, "return import(specifier)") wrapper is
            # an intentional compatibility mechanism for native dynamic import,
            # not arbitrary code generation. Do not report it as CWE-94.
            if rule.get("id") == "NODE_UNSAFE_EVAL_VM_FUNCTION" and _is_intentional_dynamic_import_function(source, match):
                continue

            # JavaScript method names are not interchangeable security sinks.
            # RegExp.prototype.exec() is pattern matching, not OS command execution.
            if rule.get("id") in {"NODE_CHILD_PROCESS_EXEC", "NODE_IMPORTED_CHILD_PROCESS_EXEC"} and language in {"javascript", "typescript"}:
                line_start = source.rfind("\n", 0, match.start()) + 1
                line_end = source.find("\n", match.end())
                if line_end == -1:
                    line_end = len(source)
                line_text = source[line_start:line_end]
                direct_sink = re.search(r"\bchild_process\.(?:exec|execSync|execFile|execFileSync)\s*\(", line_text, re.I)
                imported_exec = bool(re.search(r"(?:from\s*[\"\'](?:node:)?child_process|require\s*\(\s*[\"\'](?:node:)?child_process)", source, re.I))
                bare_call = re.search(r"(?<![.\w])(?:exec|execSync|execFile|execFileSync)\s*\(", line_text, re.I)
                # RegExp(...).exec() and arbitrary object.exec() are never command sinks.
                if not direct_sink and not (imported_exec and bare_call):
                    continue

            if rule.get("id") == "GENERIC_ZIPSLIP":
                # Require an actual extraction/write API in the same bounded context.
                context = source[max(0, match.start()-180):min(len(source), match.end()+180)]
                if not re.search(r"(?:extractToDirectory|extractToFile|extractAll|extract\s*\(|writeFile(?:Sync)?\s*\(|createWriteStream\s*\(|FileOutputStream\s*\(|OpenFile\s*\()", context, re.I):
                    continue

            # Do not suppress JAVA_XXE_PARSER because an unrelated XPath
            # evaluate()/compile() call exists elsewhere in the file. XML parser
            # construction remains an independent XXE risk signal -- unless the
            # file hardens the parser itself, which is not a signal but the fix.
            if rule.get("id") == "JAVA_XXE_PARSER" and _java_xxe_parser_hardened(source):
                continue

            # V1.12b: the file-access window rule matches ``filename`` inside
            # a variable NAME, not a value. Discard the finding only when the
            # bounded abstract evaluation PROVES every identifier in the
            # call's argument list is a compile-time constant at the sink
            # line -- no attacker input can then reach the path. Every
            # "not proven" outcome keeps the finding byte-identical.
            if rule.get("id") == "JAVA_PATH_TRAVERSAL_FILE" and _java_path_arg_proven_constant(
                source, match, filepath
            ):
                continue

            if rule.get("id") == "RUST_SQL_SINK":
                # F7 one-hop gate (kill-only for this rule): a borrowed
                # SQL string reaches a rusqlite execution sink only when
                # THIS file builds that variable with format! and a SQL
                # template (SELECT/INSERT/UPDATE/DELETE) -- the measured
                # vulnerable.rs shape (`let sql = format!("SELECT ...
                # '{}'", user); conn.prepare(&sql)`).  The bounded span
                # tolerates a wrapped `let x =\n    format!(...)`; every
                # unproven borrower stays dark, which is what keeps the
                # parameterised safe.rs form (`prepare("... ?1")`,
                # literal, never matches the pattern) and handles like
                # `prepare(&self.query)` or a non-SQL format! template
                # out of the results.
                _rsx_var = (match.groupdict() or {}).get("rsx_sql_var") or ""
                if not _rsx_var or not re.search(
                        r"\b%s\b\s*=[\s\S]{0,160}?format!\s*\(\s*\""
                        r"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE)"
                        % re.escape(_rsx_var), source, re.I):
                    continue

            lineno, snippet = _snippet_for_match(rule, source, lines, match.start(), match.end())
            if _is_comment(snippet, language):
                continue
            finding = _make_finding(rule, filepath, lineno, snippet, language)
            # Batch-10 regex validators resolve the request source in their
            # own window; carry that chain so report-side evidence gates
            # (EVIDEX sink contract, path_traversal occurrence gate) can see
            # the source-to-sink evidence instead of deleting the finding.
            if finding["rule_id"] in _PHP_SINK_CATEGORY:
                finding["sink_category"] = _PHP_SINK_CATEGORY[finding["rule_id"]]
                chain = _php_rule_taint_chain(finding["rule_id"], source, match)
                if chain:
                    finding["taint_path"] = chain
            findings.append(finding)

    return findings


def summarize_enterprise_controls(findings: list[dict]) -> dict:
    ef = [f for f in findings if f.get("enterprise_control") or str(f.get("rule_id", "")).startswith(("JAVA_","SPRING_","DOTNET_","NODE_","GO_","PHP_","GRAPHQL_","KAFKA_","GENERIC_"))]
    by_language = Counter(f.get("language", "unknown") for f in ef)
    by_rule = Counter(f.get("rule_id", "UNKNOWN") for f in ef)
    by_sev = Counter(f.get("severity", "Unknown") for f in ef)
    by_engine = Counter(f.get("engine", "scanner.sast") for f in ef)
    def cnt(pred):
        return sum(1 for f in ef if pred(f))
    return {
        "total_new_enterprise_controls": len(ef),
        "by_language": dict(by_language),
        "by_rule_id": dict(by_rule),
        "by_severity": dict(by_sev),
        "by_engine": dict(by_engine),
        "spring_boot_findings": cnt(lambda f: str(f.get("rule_id", "")).startswith("SPRING_") or "Spring" in f.get("title", "")),
        "deserialization_findings": cnt(lambda f: "deserialization" in f.get("vuln_type", "")),
        "xxe_findings": cnt(lambda f: f.get("vuln_type") == "xxe"),
        "mass_assignment_findings": cnt(lambda f: f.get("vuln_type") == "mass_assignment"),
        "redos_findings": cnt(lambda f: f.get("vuln_type") == "redos"),
        "race_async_findings": cnt(lambda f: f.get("vuln_type") in {"race_condition", "async_security_context_loss"}),
        "api_abuse_findings": cnt(lambda f: f.get("vuln_type") == "api_rate_limit"),
    }


def scan_directory(target_path: str, workers: int = 2) -> list[dict]:
    target = Path(target_path)
    # T-0.2: consume the one walk's index; no re-walk of the tree here.
    all_files = file_index.index_for(target).files(pred=_should_scan)
    all_findings: list[dict] = []

    # A1b corpus pre-pass: prove which $_SESSION keys carry request data
    # before the workers start (they only read the published set).
    try:
        _collect_corpus_session_keys(target)
    except Exception:
        pass

    def _scan(fp: Path) -> list[dict]:
        results = scan_file(str(fp))
        # Keep existing Python taint integration and add non-Python taint-like scanner.
        taint_ok = False
        try:
            from scanner.taint_engine import analyze_file as taint_analyze
            results += taint_analyze(str(fp))
            taint_ok = True
        except Exception:
            pass
        # G-037: gate only when the taint engine actually ran. If it raised,
        # the missing corroboration is an engine failure and not a fact about
        # the code, so the regex findings are left exactly as they were.
        if taint_ok:
            results = _gate_shell_sink_findings(results)
        # Phase 3.2: AST validation for the closed set of window rules whose
        # line-shape guesses a syntax tree can disprove (kill), repair
        # (re-anchor to the sink / unsafe-argument statement), or must leave
        # alone. No grammar installed, unparseable file, or validator doubt
        # all leave the findings exactly as the engines produced them.
        try:
            from scanner.ast_validators import apply_ast_validation
            results = apply_ast_validation(results, str(fp))
        except Exception:
            pass
        return results

    with ThreadPoolExecutor(max_workers=max(1, int(workers or 1))) as pool:
        futures = {pool.submit(_scan, fp): fp for fp in all_files}
        for future in as_completed(futures):
            try:
                all_findings.extend(future.result())
            except Exception:
                continue


    # RSECOPSX_J5_BIGBANG_PROJECT_INTEGRATION_V1
    # Cross-file Java analysis runs after the normal per-file worker pool.
    # Controlled by RSECOPSX_ENABLE_J5; default remains ON.
    import os as _os
    _j5_enabled = _os.environ.get(
        "RSECOPSX_ENABLE_J5", "1"
    ).strip().lower() not in {"0", "false", "off", "no"}

    if _j5_enabled:
        try:
            from scanner.java_semantic_j5 import analyze_java_project as _j5_project_scan
            _j5_findings = _j5_project_scan(str(target_path))

            # Java servlet rules for weaknesses the J5 fixpoint does not reach.
            #
            # Measured against the BenchmarkJava oracle: CWE-79 XSS detected
            # 58 of 246, and CWE-614 cookie flags 0 of 36 because no rule existed.
            # Both are wired here, deduplicated on (vuln_type, file, line) the same
            # way, and each finding carries its own confidence and note so a
            # METHOD_SCOPED pattern match is never presented as a confirmed taint
            # path.
            try:
                from scanner.java_web_servlets import scan_java_web_servlets

                _servlet_findings = []
                # `target`, not `target_path`: the parameter is a str and has
                # no rglob, so this raised AttributeError on every single run
                # and the guard below reported "servlet rules unavailable".
                # The rules themselves were fine -- they simply never
                # executed, on any target, until now.
                # T-0.2: index query; the dir exclusions (.git/target/build/
                # __pycache__/node_modules) are walk policy now, so only the
                # test/tests exclusion remains engine-local (parity).
                for _jp in file_index.index_for(target).files(exts={".java"}):
                    if any(seg in {"test", "tests"} for seg in _jp.parts):
                        continue
                    try:
                        _src = file_index.read_source(_jp)
                    except OSError:
                        continue
                    if _src is None:
                        continue
                    for _sf in scan_java_web_servlets(_src, str(_jp)):
                        _sf["file"] = str(_jp)
                        _servlet_findings.append(_sf)
            except Exception as _servlet_error:  # fail open, never silently empty
                # This handler has to actually report.  It used to call
                # _safe_print(), which is not defined in this module, so the
                # NameError raised here escaped to the outer `except Exception:
                # pass` further down.  Two things went with it: the
                # diagnostic, and the `_servlet_findings = []` below --
                # without which the J5 merge raised UnboundLocalError and
                # every cross-file Java finding was dropped as well.  Measured
                # before the fix: a forced servlet failure returned zero
                # findings and printed nothing.
                _LOG.warning("       ! servlet rules unavailable: %s", _servlet_error)
                _servlet_findings = []

            _existing_j5_keys = {
                (
                    str(f.get("vuln_type", "")),
                    str(f.get("file", "")),
                    int(f.get("line") or 0),
                    str(f.get("sink_call", "")),
                )
                for f in all_findings
                if isinstance(f, dict)
            }

            for _jf in list(_j5_findings) + _servlet_findings:
                _jk = (
                    str(_jf.get("vuln_type", "")),
                    str(_jf.get("file", "")),
                    int(_jf.get("line") or 0),
                    str(_jf.get("sink_call", "")),
                )

                if _jk not in _existing_j5_keys:
                    all_findings.append(_jf)
                    _existing_j5_keys.add(_jk)

        except Exception as _semantic_error:
            # Optional semantic layer must never break the baseline scanner.
            # It must also not vanish: this is the handler the servlet bug
            # escaped through, so it is logged rather than left a bare pass.
            _LOG.debug("optional semantic layer skipped: %s", _semantic_error)
    # Phase 6: model-artifact analysis -- static pickle-opcode extraction and
    # safetensors structure checks (scanner/model_artifact.py). Native
    # technique: the artifact is DISASSEMBLED with pickletools, never
    # unpickled. Optional layer: RSX_MODEL_ARTIFACT_SCAN=0 or any failure
    # leaves every other finding untouched.
    try:
        from scanner.model_artifact import scan_model_artifacts as _artifact_scan
        all_findings.extend(_artifact_scan(target))
    except Exception as _artifact_error:
        _LOG.warning("       ! model artifact scan unavailable: %s", _artifact_error)

    grouped = group_findings(all_findings)
    return grouped


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    data = scan_directory(target)
    print(json.dumps({"findings": data, "enterprise_control_summary": summarize_enterprise_controls(data)}, indent=2))


