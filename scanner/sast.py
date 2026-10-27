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
EXCLUDED_FILES = {
    "bom.json", "clean_report.json", "scan_manifest.json", "sbom.json", "cbom.json",
    "aibom.json", "mlbom.json", "apibom.json", "abom.json", "sarif.json", "qbom.json",
    # Prefixed artifacts. Matching is by exact filename, lowercased, so a bare
    # "qbom.json" entry does not cover "Security_QBOM.qbom.json" and the scanner
    # reads its own output back as scanned input. Every name main.py writes through
    # output_dir is listed, verified against the write sites rather than assumed.
    "security_qbom.pq.json", "security_qbom.qbom.json",
    "security_cyclonedx.json", "security_report.vex.json",
    "security_spdx.spdx.json", "scan_performance.json",
    # Phase 4: the CycloneDX 1.6 CBOM/AI-BOM artifacts. Same hazard as every
    # entry above -- written into output_dir, then read back as scan input on
    # a re-scan of the same directory.
    "security_cbom.cdx.json", "security_aibom.cdx.json",
    # Phase 5.2/5.4 integration artifacts. The CSV is not a scannable
    # extension but is listed per the "every name main.py writes" convention;
    # the two JSONs ARE a self-scan hazard. They were missed when shipped
    # because their write sites live inside reporting/webhook_export.py
    # (helper-module writes), which the self-scan guard's discovery regex
    # could not see -- the guard now scans reporting/ too.
    "security_jira_import.csv", "security_findings_webhook.json",
    "security_defectdojo_import.json",
    # Phase 5.3: the continuous re-evaluation artifact writes BESIDE a
    # caller-supplied clean_report.json by default, so it can land in a
    # directory that is later re-scanned.
    "security_continuous.json",
}

# qbom.json added with the Quantum BOM artifact (CERT-In v2.0 Table 8). The handoff
# lists this exact hazard: a new artifact filename must be excluded or the scanner
# reads its own output back as scanned input.
EXCLUDED_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", "venv", ".venv",
    "env", ".env", "dist", "build", ".cache", "vendor", "third_party", "migrations",
    "reports", "artifacts", "output", "outputs", "coverage", ".pytest_cache",
    # I2 (2026-10-19, prodtest/ethernaut): forge build artifacts live in
    # contracts/out/ and are committed but generated (397 files; 14 FP rows:
    # an IPFS CID as an AWS key, methodIdentifiers as credentials, an ABI
    # "log" function in PROMPT_RESPONSE). Sibling output dirs ("output",
    # "outputs", "artifacts") were already excluded; "out" was not.
    "out",
    # I18 (2026-10-26, aclean report): i18n property bundles under
    # src/main/resources/bundle/ are translation files, not source. Their
    # values contain credential-shaped words ("password", "token", "secret")
    # in 12 languages, producing 64 CONFIG_CONTEXTUAL_CREDENTIAL findings
    # per file. "bundle" is the standard Maven/Gradle location for i18n
    # resource bundles.
    "bundle",
}

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".scala": "scala", ".go": "go", ".php": "php",
    ".cs": "csharp", ".vb": "vbnet", ".xml": "xml", ".properties": "properties",
    ".rs": "rust",
    # 2026-10-21 batch-10: railsgoat G15 -- .rb fell through to the bare
    # "rb" fallback, so every ruby-language-gated rule (RUBY_RAILS_SECRET_TOKEN)
    # was dead. Mapping the extension is what activates the langs gate; no
    # other rule lists "ruby" today, so nothing else changes behavior.
    ".rb": "ruby",
    # 2026-10-23 G7: .sol had no mapping (and was not in SCANNABLE_EXT), so
    # Solidity sources never reached the rule loop at all. .erb likewise:
    # Rails templates are where the ERB XSS shape actually lives.
    ".sol": "solidity",
    ".erb": "ruby",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".graphql": "graphql", ".gql": "graphql",
}

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

ENTERPRISE_RULES: list[dict] = [
    {"id":"NODE_CHILD_PROCESS_EXEC","title":"Node.js child_process.exec Command Execution","vuln":"command_injection","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"\bchild_process\.(?:exec|execSync|execFile|execFileSync)\s*\("},
    {"id":"NODE_IMPORTED_CHILD_PROCESS_EXEC","title":"Node.js imported child_process.exec Command Execution","vuln":"command_injection","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"(?<![.\w])(?:exec|execSync|execFile|execFileSync)\s*\("},
    # Python
    # L1 (2026-10-21, prodtest/llama_index vs FortiCNAPP INTEG-TLS-001): the
    # tls_bypass family covered Go/PHP/.NET only, and crypto_misuse_engine's
    # CERT_VALIDATION_DISABLED table is enrichment over already-existing
    # findings (main.py:3962 summary payload) so it never creates one --
    # Python requests/urllib3/httpx certificate-validation disables were
    # invisible (llama vectara/base.py:107 missed while CNAP reported it).
    # Anchored on the API surfaces requests/httpx/ssl actually use; the scan
    # loop already drops comment and docstring/string matches.
    {"id":"PY_TLS_CERT_VALIDATION_DISABLED","title":"Python TLS Certificate Validation Disabled","vuln":"tls_bypass","sev":"Critical","langs":["python"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"\bverify\s*=\s*False\b|\bcheck_hostname\s*=\s*False\b|ssl\._create_unverified_context\s*\(|verify_mode\s*=\s*ssl\.CERT_NONE"},

    # Cookie security flags (2026-10-21, prodtest/pygoat vs CNAP): pygoat
    # dockerized_labs/broken_auth_lab/app.py:49/51 calls set_cookie without
    # secure/httponly/samesite -- CNAP DATA-COOKIE-001/002 + INTEG-COOKIE-001,
    # 6 Medium findings, source-verified. One rule per missing flag (the same
    # per-flag decomposition the Java CWE-614 servlet rule uses); the guard
    # extracts the call's argument region and reports only that flag.
    # Each flag carries its OWN vuln_type: core.deduplicator.root_key() is
    # (vuln_type, file, line), so a shared family name would collapse the
    # three claims into one per call and the last rule would never survive
    # (measured on the pygoat after-scan: SAMESITE 0 of 14 source calls).
    # The CWEs (614/1004/1275) are distinct, so the taxonomy is not stretched.
    {"id":"PY_COOKIE_MISSING_SECURE","title":"Cookie Missing Secure Flag","vuln":"insecure_cookie_secure_flag","sev":"Medium","langs":["python"],"cwe":"CWE-614","owasp":"A05:2021 - Security Misconfiguration","pat":r"\.set_cookie\s*\("},
    {"id":"PY_COOKIE_MISSING_HTTPONLY","title":"Cookie Missing HttpOnly Flag","vuln":"insecure_cookie_httponly_flag","sev":"Medium","langs":["python"],"cwe":"CWE-1004","owasp":"A04:2021 - Insecure Design","pat":r"\.set_cookie\s*\("},
    {"id":"PY_COOKIE_MISSING_SAMESITE","title":"Cookie Missing SameSite Restriction","vuln":"insecure_cookie_samesite_flag","sev":"Medium","langs":["python"],"cwe":"CWE-1275","owasp":"A05:2021 - Security Misconfiguration","pat":r"\.set_cookie\s*\("},
    # Django views explicitly exempted from CSRF (2026-10-21, prodtest): CNAP
    # INTEG-ORIGIN-002 anchors @csrf_exempt on pygoat introduction/apis.py,
    # mitre.py, playground (10) and crAPI mechanic/views.py:54 -- every one a
    # real decorator. Java (csrf().disable) and Express (csurf-missing) already
    # had coverage; the decorator arm is presence-based and cannot fire on the
    # import line (no @) or in comments (loop-level suppression).
    {"id":"DJANGO_CSRF_EXEMPT","title":"Django View Exempted from CSRF Protection","vuln":"auth_misconfiguration","sev":"Medium","langs":["python"],"cwe":"CWE-352","owasp":"A01:2021 - Broken Access Control","pat":r"@(?:method_decorator\s*\(\s*)?csrf_exempt\b"},

    # Java / Spring Boot
    {"id":"JAVA_OBJECTINPUTSTREAM_DESERIALIZATION","title":"Java ObjectInputStream Insecure Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"new\s+ObjectInputStream\s*\(|\.readObject\s*\("},
    {"id":"JAVA_JACKSON_DEFAULT_TYPING","title":"Jackson Unsafe Default Typing","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|DefaultTyping\.|@JsonTypeInfo"},
    {"id":"JAVA_SNAKEYAML_UNSAFE_LOAD","title":"SnakeYAML Unsafe Load","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"new\s+Yaml\s*\([^)]*\)\s*\.load\s*\(|Yaml\s+\w+\s*=\s*new\s+Yaml\s*\([^)]*\)"},
    {"id":"JAVA_XSTREAM_DESERIALIZATION","title":"XStream Insecure Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"new\s+XStream\s*\(|\.fromXML\s*\("},
    {"id":"JAVA_JNDI_LOG4SHELL_LOOKUP","title":"JNDI / Log4Shell-style Lookup Pattern","vuln":"jndi_injection","sev":"Critical","langs":["java","properties","xml","yaml"],"cwe":"CWE-917","owasp":"A03:2021 - Injection","pat":r"\$\{\s*jndi\s*:\s*(?:ldap|rmi|dns|iiop)://|InitialContext\s*\(|\.lookup\s*\("},
    {"id":"JAVA_JDBC_SQL_CONCAT","title":"JDBC SQL Concatenation","vuln":"sql_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"(?:createStatement\s*\(\s*\)|prepareStatement\s*\(\s*\"[^\"]*\"\s*\+|executeQuery\s*\(\s*\"[^\"]*\"\s*\+)"},
    {"id":"JAVA_HQL_JPQL_INJECTION","title":"Hibernate HQL / JPQL Injection","vuln":"orm_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"createQuery\s*\(\s*\"[^\"]*(?:from|select|where)[^\"]*\"\s*\+|@Query\s*\(\s*\"[^\"]*\"\s*\+"},
    {"id":"JAVA_JOOQ_RAW_SQL","title":"jOOQ Raw SQL Injection Indicator","vuln":"orm_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"DSL\.query\s*\(\s*\"[^\"]*\"\s*\+|fetch\s*\(\s*\"[^\"]*\"\s*\+"},
    # XPath query built by concatenating a variable into an XPath expression.
    # The literal must contain an XPath construct ([@attr=, //, text(), etc.)
    # and the file must use the XPath API (guard), so URL/HTML path building is
    # not a false positive. BenchmarkJava xpathi tests are 0/15 without this.
    {"id":"JAVA_XPATH_INJECTION","title":"Java XPath Query Built by Concatenation","vuln":"xpath_injection","sev":"High","langs":["java"],"cwe":"CWE-643","owasp":"A03:2021 - Injection","pat":r"\"[^\"]*(?:\[@|//|text\(\)|contains\(|starts-with\()[^\"]*\"\s*\+\s*\w+"},
    {"id":"JAVA_XXE_PARSER","title":"Java XML Parser XXE Risk","vuln":"xxe","sev":"High","langs":["java"],"cwe":"CWE-611","owasp":"A05:2021 - Security Misconfiguration","pat":r"DocumentBuilderFactory\.newInstance\s*\(|SAXParserFactory\.newInstance\s*\(|XMLInputFactory\.newInstance\s*\(|SAXReader\s*\("},
    {"id":"JAVA_REFLECTION_SETACCESSIBLE","title":"Dangerous Reflection setAccessible(true)","vuln":"dangerous_reflection","sev":"High","langs":["java"],"cwe":"CWE-470","owasp":"A01:2021 - Broken Access Control","pat":r"\.setAccessible\s*\(\s*true\s*\)"},
    {"id":"JAVA_PATH_TRAVERSAL_FILE","title":"Java Path Traversal File Access","vuln":"path_traversal","sev":"High","langs":["java"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"new\s+File\s*\([^)]*(?:request|getParameter|path|filename)|Paths\.get\s*\([^)]*(?:request|getParameter|path|filename)"},
    {"id":"JAVA_TLS_TRUST_BYPASS","title":"Java TLS TrustManager / HostnameVerifier Bypass","vuln":"tls_bypass","sev":"Critical","langs":["java"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"X509TrustManager|HostnameVerifier|verify\s*\([^)]*\)\s*\{\s*return\s+true|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"},
    {"id":"SPRING_SPEL_INJECTION","title":"Spring SpEL Injection Indicator","vuln":"spel_injection","sev":"Critical","langs":["java"],"cwe":"CWE-94","owasp":"A03:2021 - Injection","pat":r"SpelExpressionParser|parseExpression\s*\([^)]*(?:request|getParameter|input|param)"},
    {"id":"SPRING_MASS_ASSIGNMENT_ENTITY_BINDING","title":"Spring MVC Mass Assignment Entity Binding","vuln":"mass_assignment","sev":"High","langs":["java"],"cwe":"CWE-915","owasp":"A01:2021 - Broken Access Control","pat":r"@(RequestBody|ModelAttribute)\s+(?:User|Account|Admin|Role|Customer|Order|.*Entity)\b"},
    {"id":"SPRING_SECURITY_CSRF_DISABLED","title":"Spring Security CSRF Disabled","vuln":"auth_misconfiguration","sev":"Critical","langs":["java"],"cwe":"CWE-352","owasp":"A01:2021 - Broken Access Control","pat":r"csrf\s*\(\s*\)\s*\.disable\s*\(|csrf\s*\(\s*csrf\s*->\s*csrf\.disable\s*\("},
    {"id":"SPRING_PERMITALL_BROAD_MATCHER","title":"Spring Security Broad permitAll Exposure","vuln":"auth_misconfiguration","sev":"Critical","langs":["java"],"cwe":"CWE-284","owasp":"A01:2021 - Broken Access Control","pat":r"(?:antMatchers|requestMatchers)\s*\([^)]*(?:/\*\*|\*)[^)]*\)\s*\.permitAll\s*\("},
    {"id":"SPRING_ACTUATOR_EXPOSE_ALL","title":"Spring Actuator All Endpoints Exposed","vuln":"actuator_exposure","sev":"Critical","langs":["properties","yaml","java"],"cwe":"CWE-200","owasp":"A05:2021 - Security Misconfiguration","pat":r"management\.endpoints\.web\.exposure\.include\s*=\s*\*|exposure:\s*\n\s*include:\s*[\"']?\*[\"']?"},
    {"id":"SPRING_MULTIPART_TRAVERSAL","title":"Spring MultipartFile Unsafe Upload Path","vuln":"path_traversal","sev":"High","langs":["java"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"MultipartFile|getOriginalFilename\s*\(\s*\)|transferTo\s*\(\s*new\s+File"},
    {"id":"SPRING_ASYNC_CONTEXT_LOSS","title":"Spring @Async Security Context Loss Indicator","vuln":"async_security_context_loss","sev":"High","langs":["java"],"cwe":"CWE-362","owasp":"A04:2021 - Insecure Design","pat":r"@Async(?![\s\S]{0,250}(DelegatingSecurityContext|SecurityContextHolder))"},
    {"id":"SPRING_CACHEABLE_USER_KEY","title":"Spring @Cacheable User-Controlled Key","vuln":"cache_key_injection","sev":"Medium","langs":["java"],"cwe":"CWE-20","owasp":"A04:2021 - Insecure Design","pat":r"@Cacheable\s*\([^)]*key\s*=\s*[\"'][^\"']*#(?:user|request|param|id)"},
    {"id":"JAVA_TEMPLATE_INJECTION","title":"Java Template Injection Indicator","vuln":"template_injection","sev":"High","langs":["java"],"cwe":"CWE-94","owasp":"A03:2021 - Injection","pat":r"TemplateEngine\.process\s*\([^)]*(?:request|getParameter)|Freemarker|VelocityEngine|StringTemplateResolver"},
    {"id":"SPRING_WEBFLUX_AUTH_GAP","title":"Spring WebFlux Authorization Propagation Gap","vuln":"auth_misconfiguration","sev":"High","langs":["java"],"cwe":"CWE-284","owasp":"A01:2021 - Broken Access Control","pat":r"RouterFunctions\.route\s*\(|SecurityWebFilterChain|authorizeExchange\s*\(\s*\)\s*\.anyExchange\s*\(\s*\)\s*\.permitAll"},
    {"id":"SPRING_MISSING_VALIDATION","title":"Spring Missing @Valid / @Validated Indicator","vuln":"missing_validation","sev":"Medium","langs":["java"],"cwe":"CWE-20","owasp":"A04:2021 - Insecure Design","pat":r"@(PostMapping|PutMapping|PatchMapping)[\s\S]{0,250}@(RequestBody|ModelAttribute)(?![\s\S]{0,80}@(?:Valid|Validated))"},

    # C# / .NET
    {"id":"DOTNET_BINARYFORMATTER","title":".NET BinaryFormatter Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["csharp"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"BinaryFormatter\s*\(|\.Deserialize\s*\("},
    {"id":"DOTNET_TYPENAMEHANDLING","title":"Json.NET TypeNameHandling Unsafe","vuln":"insecure_deserialization","sev":"Critical","langs":["csharp"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)"},
    {"id":"DOTNET_DATACONTRACT_DESERIALIZER","title":"DataContractSerializer Unsafe Deserialization","vuln":"insecure_deserialization","sev":"High","langs":["csharp"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"DataContractSerializer\s*\(|NetDataContractSerializer\s*\("},
    {"id":"DOTNET_ADO_SQL_CONCAT","title":"ADO.NET SQL Concatenation","vuln":"sql_injection","sev":"High","langs":["csharp"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"SqlCommand\s*\(\s*\"[^\"]*\"\s*\+|CommandText\s*=\s*\"[^\"]*\"\s*\+"},
    {"id":"DOTNET_EF_FROMSQLRAW_INTERPOLATION","title":"Entity Framework FromSqlRaw Interpolation","vuln":"orm_injection","sev":"High","langs":["csharp"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"FromSqlRaw\s*\(\s*\$\"|FromSqlRaw\s*\([^)]*\+"},
    {"id":"DOTNET_XXE_DTD_PROCESSING","title":".NET XML DTD Processing / XXE","vuln":"xxe","sev":"High","langs":["csharp"],"cwe":"CWE-611","owasp":"A05:2021 - Security Misconfiguration","pat":r"DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver|XmlDocument\s*\("},
    {"id":"DOTNET_PATH_COMBINE_TRAVERSAL","title":".NET Path.Combine Traversal Indicator","vuln":"path_traversal","sev":"High","langs":["csharp"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"Path\.Combine\s*\([^)]*(?:Request|Query|Form|Route|file|path|name)"},
    {"id":"DOTNET_ZIPSLIP_EXTRACT","title":".NET ZipSlip Extraction Risk","vuln":"zipslip","sev":"High","langs":["csharp"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"ZipFile\.ExtractToDirectory\s*\("},
    {"id":"DOTNET_OVERPOSTING","title":"ASP.NET Mass Assignment / Overposting","vuln":"mass_assignment","sev":"High","langs":["csharp"],"cwe":"CWE-915","owasp":"A01:2021 - Broken Access Control","pat":r"public\s+(?:IActionResult|Task<[^>]+>)\s+\w+\s*\([^)]*(?:User|Account|Role|Admin|.*Entity)\s+\w+"},
    {"id":"DOTNET_OPEN_REDIRECT","title":"ASP.NET Open Redirect","vuln":"open_redirect","sev":"High","langs":["csharp"],"cwe":"CWE-601","owasp":"A01:2021 - Broken Access Control","pat":r"Redirect\s*\(\s*(?:returnUrl|url|Request\.)"},
    {"id":"DOTNET_CERT_VALIDATION_BYPASS","title":"HttpClient Certificate Validation Bypass","vuln":"tls_bypass","sev":"Critical","langs":["csharp"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"ServerCertificateCustomValidationCallback\s*=\s*.*=>\s*true|DangerousAcceptAnyServerCertificateValidator"},
    {"id":"DOTNET_LOG_INJECTION","title":"ILogger Raw User Input Log Injection","vuln":"log_injection","sev":"Medium","langs":["csharp"],"cwe":"CWE-117","owasp":"A09:2021 - Security Logging and Monitoring Failures","pat":r"ILogger|_logger\.(?:Information|Error|Warning|Debug)\s*\([^)]*(?:Request|Query|Form|Headers|userInput)"},
    {"id":"DOTNET_HARDCODED_CREDENTIAL","title":".NET Hardcoded Credential in String Declaration","vuln":"hardcoded_secret","sev":"High","langs":["csharp"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"(?:string|var|const\s+string)\s+(?P<ident>\w+)\s*=\s*\"[^\"]{8,}\""},
    {"id":"DOTNET_PROCESS_START_INFO","title":".NET ProcessStartInfo with User-Controlled Arguments","vuln":"command_injection","sev":"Critical","langs":["csharp"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"ProcessStartInfo\s*\([^)]*\w+|\.Start\s*\(\s*\)"},
    {"id":"DOTNET_COMMAND_CONCAT","title":".NET Command Arguments String Concatenation","vuln":"command_injection","sev":"Critical","langs":["csharp"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"Arguments\s*=\s*\"[^\"]*(?:/c |/k |cmd\.exe|powershell|bash)[^\"]*\"\s*\+\s*\w+"},
    {"id":"DOTNET_SQL_INTERPOLATED","title":".NET SqlCommand with Interpolated SQL String","vuln":"sql_injection","sev":"High","langs":["csharp"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"SqlCommand\s*\(\s*\$\"|\.ExecuteReader\s*\(\s*\)|\.ExecuteScalar\s*\(\s*\)"},

    # Node / TypeScript
    {"id":"NODE_PROTOTYPE_POLLUTION_MERGE","title":"Node Prototype Pollution Merge","vuln":"prototype_pollution","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-1321","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"Object\.assign\s*\([^)]*(?:req\.|body|query)|(?:lodash|_|deepmerge|merge)\.merge\s*\([^)]*(?:req\.|body|query)|qs\.parse\s*\("},
    {"id":"NODE_CHILD_PROCESS_EXEC","title":"Node child_process.exec Command Injection","vuln":"command_injection","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"child_process\.(?:exec|execSync|execFile|execFileSync)\s*\(|(?:\bexec|execSync)\s*\([^)]*(?:req\.|query|body)"},
    {"id":"NODE_UNSAFE_EVAL_VM_FUNCTION","title":"Node Unsafe eval/vm/new Function","vuln":"code_injection","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-94","owasp":"A03:2021 - Injection","pat":r"\beval\s*\(|new\s+Function\s*\(|vm\.runIn(?:This|New)Context\s*\("},
    {"id":"NODE_FS_TRAVERSAL","title":"Node fs Path Traversal Indicator","vuln":"path_traversal","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"fs\.(?:readFile|writeFile|createReadStream|unlink)\s*\([^)]*(?:req\.|query|body|params)"},
    {"id":"NODE_SERIALIZE_UNSERIALIZE","title":"node-serialize Unsafe Unserialize","vuln":"insecure_deserialization","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"node-serialize|\.unserialize\s*\("},
    {"id":"NODE_JSYAML_UNSAFE_LOAD","title":"js-yaml Unsafe load","vuln":"insecure_deserialization","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"jsyaml\.load\s*\(|yaml\.load\s*\("},
    {"id":"NODE_SSRF_DYNAMIC_URL","title":"Node SSRF Dynamic URL","vuln":"ssrf","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-918","owasp":"A10:2021 - Server-Side Request Forgery","pat":r"(?:fetch|axios\.(?:get|post|request)|http\.request|https\.request)\s*\([^)]*(?:req\.|query|body|params|url)"},
    {"id":"NODE_REDOS_REGEX","title":"Node ReDoS Catastrophic Regex","vuln":"redos","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-1333","owasp":"A05:2021 - Security Misconfiguration","pat":r"new\s+RegExp\s*\([^)]*(?:req\.|query|body)|/\([^/]*\+\)[+*]|/\([^/]*\*\)[+*]"},
    {"id":"NPM_SUPPLY_CHAIN_SCRIPT","title":"NPM Supply Chain Lifecycle Script / Unpinned Dependency","vuln":"supply_chain_script","sev":"Medium","langs":["json"],"cwe":"CWE-829","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"\"(?:preinstall|postinstall|prepare)\"\s*:|\"(?:dependencies|devDependencies)\"\s*:\s*\{[\s\S]*\"[^\"]+\"\s*:\s*\"(?:\*|latest|http|git\+)"},
    # JS/TS SQL injection via template-literal interpolation. Parameterized
    # queries use ? / :name placeholders; interpolating ${...} directly into a
    # SQL string passed to query()/raw() is injection. Confirmed on juice-shop
    # routes/login.ts:34 (sequelize.query(`SELECT ... '${req.body.email}'`)).
    {"id":"NODE_SQL_TEMPLATE_INTERPOLATION","title":"JavaScript/TypeScript SQL Built via Template-Literal Interpolation","vuln":"sql_injection","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"(?is)\.\s*(?:query|raw|rawQuery|execute)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH)\b[^`]*\$\{"},
    # Express app created with no CSRF protection for its state-changing routes.
    # A "missing control" posture indicator (not a confirmed exploit): fires only
    # when the same file registers post/put/patch/delete routes and references no
    # CSRF middleware. Confirmed on juice-shop server.ts:130.
    {"id":"EXPRESS_CSRF_MISSING","title":"Express App Missing CSRF Protection","vuln":"auth_misconfiguration","sev":"Medium","langs":["javascript","typescript"],"cwe":"CWE-352","owasp":"A01:2021 - Broken Access Control","pat":r"\bexpress\s*\(\s*\)"},
    # Open redirect from request input (2026-10-21, prodtest/NodeGoat vs CNAP
    # INPUT-REDIRECT-001): index.js:72 ``res.redirect(req.query.url)`` is a
    # source-verified High TP. Only request-derived inputs qualify --
    # req.path/req.baseUrl stay same-site and literals are not redirects of
    # user input.
    {"id":"EXPRESS_OPEN_REDIRECT","title":"Express Open Redirect from Request Input","vuln":"open_redirect","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-601","owasp":"A01:2021 - Broken Access Control","pat":r"res\.redirect\s*\(\s*[^)\n]*(?:req(?:uest)?\.(?:query|body|params|headers))"},
    # Session cookie with no lifetime (2026-10-21, prodtest/NodeGoat vs CNAP
    # AUTH-SE...): server.js:78 session({...}) block carries only
    # ``// TODO: Add "maxAge"`` -- session-scoped cookie, no expiration.
    # Guard extracts the config region, so the TODO comment (maxAge without a
    # colon) does not mask the finding; express-session must be imported.
    {"id":"EXPRESS_SESSION_COOKIE_NO_EXPIRY","title":"Session Cookie Without Expiration","vuln":"auth_misconfiguration","sev":"Medium","langs":["javascript","typescript"],"cwe":"CWE-613","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"\bsession\s*\(\s*\{"},
    # A JWT payload read via jwt.decode()/decode() in a file that imports
    # jsonwebtoken but never calls verify(). decode() does NOT check the
    # signature, so trusting its output is an authentication bypass. Files that
    # verify (the secure decode-then-verify pattern) are excluded by the guard.
    # Confirmed on juice-shop routes/authenticatedUsers.ts:20.
    {"id":"NODE_JWT_DECODE_NO_VERIFY","title":"JWT Decoded Without Signature Verification","vuln":"auth_misconfiguration","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-347","owasp":"A02:2021 - Cryptographic Failures","pat":r"\b(?:jwt\s*\.\s*)?decode\s*\("},

    # Go
    {"id":"GO_EXEC_SH_C","title":"Go exec.Command sh -c / User-Controlled Args","vuln":"command_injection","sev":"Critical","langs":["go"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"exec\.Command\s*\(\s*\"(?:sh|bash|cmd)\"\s*,\s*\"-c\"|exec\.Command\s*\([^)]*(?:r\.URL|r\.Form|Query\()"},
    {"id":"GO_FILEPATH_JOIN_TRAVERSAL","title":"Go filepath.Join Traversal","vuln":"path_traversal","sev":"High","langs":["go"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"filepath\.Join\s*\([^)]*(?:r\.URL|FormValue|Query\(|filename|path)"},
    {"id":"GO_SQL_FMT_SPRINTF","title":"Go fmt.Sprintf SQL Injection","vuln":"sql_injection","sev":"High","langs":["go"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"fmt\.Sprintf\s*\(\s*\"[^\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^\"]*\"|db\.Query\s*\([^)]*\+"},
    {"id":"GO_GOB_DECODE","title":"Go gob Decode Untrusted Data","vuln":"insecure_deserialization","sev":"High","langs":["go"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"gob\.NewDecoder\s*\(|\.Decode\s*\(&"},
    {"id":"GO_JSON_UNMARSHAL_INTERFACE","title":"Go json.Unmarshal into interface{} / any","vuln":"insecure_deserialization","sev":"Medium","langs":["go"],"cwe":"CWE-20","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"var\s+\w+\s+(?:interface\{\}|any)|json\.Unmarshal\s*\([^)]*,\s*&\w+\s*\)"},
    {"id":"GO_SSRF_HTTP_GET","title":"Go SSRF Dynamic HTTP Request","vuln":"ssrf","sev":"High","langs":["go"],"cwe":"CWE-918","owasp":"A10:2021 - Server-Side Request Forgery","pat":r"http\.(?:Get|Post)\s*\([^)]*(?:r\.URL|FormValue|Query\(|url)|http\.NewRequest\s*\([^)]*(?:r\.URL|Query\()"},
    {"id":"GO_OPEN_REDIRECT","title":"Go Open Redirect","vuln":"open_redirect","sev":"High","langs":["go"],"cwe":"CWE-601","owasp":"A01:2021 - Broken Access Control","pat":r"http\.Redirect\s*\([^)]*(?:r\.URL|FormValue|Query\()"},
    {"id":"GO_SHARED_MAP_RACE","title":"Go Shared Map/Slice Race Indicator","vuln":"race_condition","sev":"High","langs":["go"],"cwe":"CWE-362","owasp":"A04:2021 - Insecure Design","pat":r"var\s+\w+\s+map\[|go\s+func\s*\(|\w+\s*\[.*\]\s*=\s*"},
    {"id":"GO_UNBOUNDED_READALL","title":"Go Unbounded io.ReadAll / ioutil.ReadAll","vuln":"resource_exhaustion","sev":"High","langs":["go"],"cwe":"CWE-400","owasp":"A05:2021 - Security Misconfiguration","pat":r"(?:io|ioutil)\.ReadAll\s*\(\s*r\.Body\s*\)(?![\s\S]{0,200}MaxBytesReader)"},
    {"id":"GO_TLS_INSECURE_SKIP_VERIFY","title":"Go TLS InsecureSkipVerify true","vuln":"tls_bypass","sev":"Critical","langs":["go"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"InsecureSkipVerify\s*:\s*true"},
    # Weak hash usage (2026-10-21, prodtest/crAPI vs CNAP CRYPTO-WEAK-002/003):
    # the md5/sha1 rules covered Java/.NET/JS/Python only. Anchored on the
    # crypto/md5|sha1 import string and the md5.New|Sum / sha1.New|Sum calls.
    # (crAPI's own CNAP hits live under vendor/ which stays excluded by
    # EXCLUDED_DIRS policy -- this rule covers first-party Go source.)
    {"id":"GO_MD5_USAGE","title":"Go MD5 Usage","vuln":"weak_crypto","sev":"High","langs":["go"],"cwe":"CWE-327","owasp":"A02:2021 - Cryptographic Failures","pat":r"[\"']crypto/md5[\"']|\bmd5\.(?:New|Sum)\s*\("},
    {"id":"GO_SHA1_USAGE","title":"Go SHA-1 Usage","vuln":"weak_crypto","sev":"High","langs":["go"],"cwe":"CWE-327","owasp":"A02:2021 - Cryptographic Failures","pat":r"[\"']crypto/sha1[\"']|\bsha1\.(?:New|Sum)\s*\("},
    # --- batch 9 (2026-10-21, DVWA/wrongsecrets joins) ---
    # DVWA vulnerabilities/api/gen_openapi.php:6 -- CNAP INTEG-ORIGIN-001:
    # header("Access-Control-Allow-Origin: *"). Cross-language posture rule.
    # The pattern is deliberately CALL-ANCHORED (header(/setHeader(/addHeader(
    # /headers[...]=): the header NAME necessarily lives in a string literal,
    # and the JS string-content suppression at the enterprise dispatch drops
    # any match that starts inside 'Access-Control-Allow-Origin'. Anchoring
    # on the sink call keeps the match on code, and reflected-origin echoes
    # (a different defect family) stay quiet by construction -- see the test
    # controls in tests/test_lacework_prodtest_batch9_gaps_20261021.py.
    {"id":"GENERIC_CORS_WILDCARD_ORIGIN","title":"CORS Wildcard Origin","vuln":"insecure_cors_configuration","sev":"Medium","langs":["python","javascript","typescript","php","java"],"cwe":"CWE-942","owasp":"A05:2021 - Security Misconfiguration","pat":r"(?:header|setHeader|add[_]?Header)\s*\(\s*[\"'][^\"']*Access-Control-Allow-Origin\s*:\s*\*[\"']|(?:setHeader|add[_]?Header)\s*\(\s*[\"']Access-Control-Allow-Origin[\"']\s*,\s*[\"']\*[\"']|headers\s*\[\s*[\"']Access-Control-Allow-Origin[\"']\s*\]\s*=\s*[\"']\*[\"']"},
    # wrongsecrets Challenge54.java:42 + Challenge63.java:41 -- CNAP
    # CRYPTO-WEAK-002: Cipher.getInstance("AES/CBC/...") fed a static IV
    # (Challenge63 self-documents the padding oracle). The gate requires an
    # IvParameterSpec in the window AND a literal assigned to an iv-named
    # identifier, so AES/GCM with SecureRandom IVs stays quiet.
    {"id":"JAVA_CIPHER_CBC_STATIC_IV","title":"Java AES/CBC Cipher with Static IV","vuln":"weak_crypto","sev":"High","langs":["java"],"cwe":"CWE-329","owasp":"A02:2021 - Cryptographic Failures","pat":r"Cipher\.getInstance\s*\(\s*[\"'][^\"']*(?:AES|DES)/CBC"},
    # DVWA setcookie() -- CNAP DATA-COOKIE-001/002 (secure x7, httponly x6).
    # PHP's setcookie is positional (secure=arg6, httponly=arg7) with a PHP
    # 7.3+ options-array alternative; the guard handles both forms. Each flag
    # keeps its own vuln_type so core.deduplicator's (vuln_type, file, line)
    # key cannot collapse them (batch-8 lesson).
    {"id":"PHP_COOKIE_MISSING_SECURE","title":"PHP Cookie Missing Secure Flag","vuln":"insecure_cookie_secure_flag","sev":"Medium","langs":["php"],"cwe":"CWE-614","owasp":"A05:2021 - Security Misconfiguration","pat":r"setcookie\s*\("},
    {"id":"PHP_COOKIE_MISSING_HTTPONLY","title":"PHP Cookie Missing HttpOnly Flag","vuln":"insecure_cookie_httponly_flag","sev":"Medium","langs":["php"],"cwe":"CWE-1004","owasp":"A04:2021 - Insecure Design","pat":r"setcookie\s*\("},
    # --- batch 10 (2026-10-21, DVWA/WebGoat/railsgoat joins) ---
    # G9: the batch-8-era *_SQL_CONCAT rules only see SUPERGLOBAL-IN-SINK
    # shapes. Every remaining CNAP INJ-SQL-001 true positive on WebGoat (9/9)
    # and the DVWA sqli lesson builds the query in a VARIABLE a few lines
    # above the sink (`String query = "..." + param; executeQuery(query)` /
    # `$query = "SELECT ... '$id'"; mysql_query($query)`). These two rules
    # close that recall gap with window-based validators; request-input
    # evidence is still required, so config-interpolated queries (DVWA
    # includes/DBMS/MySQL.php, adjudicated as no-attacker-control) stay dark.
    {"id":"JAVA_JDBC_SQL_INTERMEDIATE_QUERY","title":"JDBC SQL via Intermediate Variable","vuln":"sql_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"\b(?:executeQuery|executeUpdate|execute)\s*\(\s*(?P<jvar>[A-Za-z_]\w*)\s*\)|prepareStatement\s*\(\s*(?P<pvar>[A-Za-z_]\w*)\s*[,)]"},
    {"id":"JAVA_JDBC_SQL_PREPARED_CONCAT","title":"PreparedStatement Built by Concatenation","vuln":"sql_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"(?i)prepareStatement\s*\(\s*[\"'][^\"']*(?:select|insert|update|delete|where)"},
    {"id":"PHP_SQL_INTERMEDIATE_QUERY","title":"PHP SQL via Intermediate Variable","vuln":"sql_injection","sev":"High","langs":["php"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"(?:mysql_query|mysqli_query|->query|PDO::query)\s*\("},
    # G16: DVWA csp/source/jsonp.php -- `echo $callback . "(" . json_encode(...)` with
    # $callback = $_GET['callback'] (JSONP callback injection). PHP_RAW_ECHO_XSS
    # only sees `echo $_GET` adjacency.
    {"id":"PHP_XSS_TAINTED_ECHO","title":"PHP echo/print of Request-Derived Value","vuln":"xss","sev":"High","langs":["php"],"cwe":"CWE-79","owasp":"A03:2021 - Injection","pat":r"(?<![\w$])(?:echo|print)\s+"},
    # G17: DVWA view_source.php / view_source_all.php -- $id/$security from
    # GET interpolated into a file_get_contents path one hop below.
    {"id":"PHP_PATH_USER_INPUT_VAR","title":"PHP File Read via Request-Derived Variable","vuln":"path_traversal","sev":"High","langs":["php"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"(?<![\w$])(?:file_get_contents|fopen|readfile|include|require|include_once|require_once)\s*\(?\s*"},
    # G18: DVWA weak_id low/medium/high -- session cookie set from time(), an
    # $_SESSION counter, or md5(counter). Client-chosen NON-session cookies
    # (cookie-input.php 'id') are a different family and stay dark.
    {"id":"PHP_SESSION_ID_PREDICTABLE","title":"PHP Predictable Session Identifier","vuln":"weak_session_identifier","sev":"Medium","langs":["php"],"cwe":"CWE-330","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"(?<![\w$])setcookie\s*\("},
    # G19: DVWA open_redirect low/medium/high -- header("location: " . $_GET).
    {"id":"PHP_OPEN_REDIRECT_HEADER","title":"PHP Open Redirect via Location Header","vuln":"open_redirect","sev":"Medium","langs":["php"],"cwe":"CWE-601","owasp":"A01:2021 - Broken Access Control","pat":r"(?i)(?<![\w$])header\s*\(\s*[\"'][^\"']*location\s*:"},
    # G20: DVWA exec medium/high + api/HealthController -- shell_exec/exec fed
    # a variable built from request input (str_replace blacklist is bypassable;
    # php://input json body is one hop away). The impossible.php hardened
    # variant (ctype_digit-validated octets) and escapeshellarg/escapeshellcmd
    # wrapping stay dark -- see the validator guards.
    {"id":"PHP_CMD_INJECTION_INTERMEDIATE","title":"PHP Command Injection via Intermediate Variable","vuln":"command_injection","sev":"Critical","langs":["php"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"(?<![\w$])(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\("},
    # G15: railsgoat config/initializers/secret_token.rb:8 -- committed Rails
    # session-signing key (128-hex). ENV references and short dev strings are
    # not key material; the language gate keeps docs/markdown examples out.
    {"id":"RUBY_RAILS_SECRET_TOKEN","title":"Rails Hardcoded Secret Key Base","vuln":"hardcoded_secret","sev":"High","langs":["ruby"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"(?:secret_key_base|secret_token)\s*=\s*[\"'][0-9A-Fa-f]{32,}[\"']"},
    # G7 Ruby arms (2026-10-23): direct request-derived source into a named
    # sink, the same honesty bar PHP_RAW_ECHO_XSS sets. Whitelisted or
    # local-variable equivalents stay dark because the source token is what
    # each pattern requires, not the sink alone.
    {"id":"RUBY_CMD_INJECTION","title":"Ruby Command Execution with Request-Derived Input","vuln":"command_injection","sev":"Critical","langs":["ruby"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"\b(?:system|exec|spawn|popen)\s*\(\s*(?:params\b|request\b)|\b(?:system|exec|spawn|popen)\s*\(\s*\"[^\"\n]*?#\{[^}]*\b(?:params|request)|`[^`\n]*#\{[^}]*\b(?:params|request)|%x[!\(\{][^)\}\n]*#\{[^}]*\b(?:params|request)|open\s*\(\s*\"\|[^\"\n]*?#\{[^}]*\b(?:params|request)"},
    {"id":"RUBY_CODE_INJECTION","title":"Ruby eval of Request-Derived Input","vuln":"code_injection","sev":"Critical","langs":["ruby"],"cwe":"CWE-94","owasp":"A03:2021 - Injection","pat":r"\b(?:eval|instance_eval|class_eval|module_eval)\s*\(\s*(?:params\b|request\b)|\b(?:eval|instance_eval|class_eval|module_eval)\s*\(\s*\"[^\"\n]*?#\{[^}]*\b(?:params|request)"},
    {"id":"RUBY_SQL_INJECTION","title":"Ruby SQL Built by String Interpolation of Request Data","vuln":"sql_injection","sev":"High","langs":["ruby"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"\.(?:where|find_by_sql|order|select_all)\s*\(\s*\"[^\"\n]*?#\{[^}]*\b(?:params|request|session\b)|\.connection\s*\.\s*execute\s*\(\s*\"[^\"\n]*?#\{[^}]*\b(?:params|request)|\bfind_by_sql\s*\(\s*(?:params\b|request\b)"},
    {"id":"RUBY_PATH_TRAVERSAL","title":"Ruby File API Fed Request Data Verbatim","vuln":"path_traversal","sev":"High","langs":["ruby"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"\bsend_file\s*\(\s*(?:params\b|request\b)|\bFile\.(?:read|open|foreach|readlines)\s*\(\s*(?:params\b|request\b)|\brender\s+file:\s*(?:params\b|request\b)"},
    {"id":"RUBY_XSS_ERB","title":"ERB Output Escaping Disabled on Request-Derived Value","vuln":"xss","sev":"High","langs":["ruby"],"cwe":"CWE-79","owasp":"A03:2021 - Injection","pat":r"<%=[^\n]*\b(?:params|request)\b[^\n]*(?:\.html_safe\b|\braw\b)|<%=[^\n]*\braw\s*\(?\s*[^\n]*\b(?:params|request)\b"},
    {"id":"RUBY_INSECURE_DESER","title":"Ruby Marshal/YAML Deserialization of Request or Cookie Data","vuln":"insecure_deserialization","sev":"Critical","langs":["ruby"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"\bMarshal\.load\s*\(\s*(?:params\b|request\b|cookies\b)|\bYAML\.(?:unsafe_load|load)\s*\(\s*(?:params\b|request\b|cookies\b)"},
    # G7 Solidity arms (2026-10-23): the three provable shapes. tx.origin in
    # an authorization comparison, a randomness-flavoured variable fed from
    # block attributes, and a low-level call whose success boolean is
    # discarded (bare statement). payable(x).call(...) receivers with
    # parentheses are outside the shipped sub-shape for SOL_UNCHECKED_CALL,
    # deliberately: the pattern anchors on a bare identifier receiver.
    {"id":"SOL_TX_ORIGIN_AUTH","title":"Solidity tx.origin Used for Authorization","vuln":"origin_confusion","sev":"High","langs":["solidity"],"cwe":"CWE-346","owasp":"A01:2021 - Broken Access Control","pat":r"\brequire\s*\([^;\n]*\btx\.origin\b|\bif\s*\(\s*[^;\n]*\btx\.origin\b|\btx\.origin\s*=="},
    {"id":"SOL_WEAK_RANDOMNESS","title":"Solidity Randomness Derived from Block Attributes","vuln":"weak_randomness","sev":"High","langs":["solidity"],"cwe":"CWE-330","owasp":"A02:2021 - Cryptographic Failures","pat":r"(?i)(?:rand\w*|nonce\w*|lottery\w*|winner\w*|shuffle\w*|jackpot\w*|raffle\w*)[^\n]{0,160}\b(?:block\.(?:timestamp|number|difficulty|prevrandao)|blockhash\s*\()|(?:block\.(?:timestamp|number|difficulty|prevrandao)|blockhash\s*\()[^\n]{0,160}(?:rand\w*|nonce\w*|lottery\w*|winner\w*|shuffle\w*|jackpot\w*|raffle\w*)"},
    {"id":"SOL_UNCHECKED_CALL","title":"Solidity Low-Level Call Result Ignored","vuln":"unchecked_call_result","sev":"Medium","langs":["solidity"],"cwe":"CWE-252","owasp":"A05:2021 - Security Misconfiguration","pat":r"(?m)^\s*[A-Za-z_$][\w$]*\s*\.\s*(?:call|staticcall|delegatecall)\s*(?:\{[^}\n]*\})?\s*\([^;\n]*\)\s*;"},
    # G-062 resurrection (2026-10-24): the only two provable shapes in
    # quarantine/scanner/business_logic_patterns.py. Everything else there
    # matches IDENTIFIER NAMES and cannot distinguish a control mention from
    # a control absence, so it stays quarantined on principle.
    {"id":"CLIENT_ASSIGNED_AMOUNT","title":"Client-Controlled Price or Amount Assignment","vuln":"client_controlled_amount","sev":"High","langs":["python","javascript","typescript","php"],"cwe":"CWE-471","owasp":"A04:2021 - Insecure Design","pat":r"\b(?:amount|price|discount|order_total|unit_price)\s*=\s*(?:request\.(?:json|form|data)|request\.get_json\(\)|request\.body|req\.body|\$_POST)"},
    {"id":"CLIENT_ASSIGNED_PRIVILEGE","title":"Client-Controlled Privilege Field Assignment","vuln":"mass_assignment","sev":"High","langs":["python","javascript","typescript","php"],"cwe":"CWE-915","owasp":"A01:2021 - Broken Access Control","pat":r"\b(?:role|is_admin|permissions|account_status)\s*=\s*(?:request\.(?:json|form|data)|request\.get_json\(\)|request\.body|req\.body|\$_POST)"},
    {"id":"GO_HARDCODED_CREDENTIAL","title":"Go Hardcoded Credential in Connection String","vuln":"hardcoded_secret","sev":"High","langs":["go"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"\w+:\w+@tcp\(|\w+:\w+@\(|\w+:\w+@/"},
    {"id":"GO_SQL_CONCAT_INTERMEDIATE","title":"Go SQL Concatenation via Intermediate Variable","vuln":"sql_injection","sev":"High","langs":["go"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"\"[^\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^\"]*\"\s*\+\s*\w+"},
    {"id":"GO_PATH_CONCAT","title":"Go Path String Concatenation with Absolute Prefix","vuln":"path_traversal","sev":"High","langs":["go"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"\"[^\"]*(?:/var/|/home/|/tmp/|/usr/|/etc/)[^\"]*\"\s*\+\s*\w+"},

    # PHP
    {"id":"PHP_LFI_RFI_INCLUDE","title":"PHP LFI/RFI include/require","vuln":"path_traversal","sev":"High","langs":["php"],"cwe":"CWE-98","owasp":"A03:2021 - Injection","pat":r"(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)"},
    {"id":"PHP_COMMAND_INJECTION","title":"PHP Command Injection Sink","vuln":"command_injection","sev":"Critical","langs":["php"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"(?:shell_exec|system|exec|passthru|popen|proc_open)\s*\([^)]*\$_(?:GET|POST|REQUEST)|`[^`]*\$_(?:GET|POST|REQUEST)"},
    {"id":"PHP_SQL_CONCAT","title":"PHP SQL Concatenation","vuln":"sql_injection","sev":"High","langs":["php"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"(?:mysqli_query|->query|PDO::query)\s*\([^)]*\$_(?:GET|POST|REQUEST)|\"\s*\.\s*\$_(?:GET|POST|REQUEST)"},
    {"id":"PHP_UNSERIALIZE","title":"PHP unserialize Object Injection","vuln":"insecure_deserialization","sev":"Critical","langs":["php"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)"},
    {"id":"PHP_SSRF_CURL_FILEGET","title":"PHP SSRF Dynamic URL","vuln":"ssrf","sev":"High","langs":["php"],"cwe":"CWE-918","owasp":"A10:2021 - Server-Side Request Forgery","pat":r"(?:curl_exec|file_get_contents|fopen)\s*\([^)]*\$_(?:GET|POST|REQUEST)|CURLOPT_URL\s*,\s*\$_"},
    {"id":"PHP_FILE_TRAVERSAL","title":"PHP File Path Traversal","vuln":"path_traversal","sev":"High","langs":["php"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"(?:fopen|unlink|file_get_contents|readfile)\s*\([^)]*\$_(?:GET|POST|REQUEST)"},
    {"id":"PHP_PHAR_DESERIALIZATION","title":"PHP PHAR Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["php"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"phar://|Phar\s*\("},
    {"id":"PHP_RAW_ECHO_XSS","title":"PHP Raw echo/print XSS","vuln":"xss","sev":"High","langs":["php"],"cwe":"CWE-79","owasp":"A03:2021 - Injection","pat":r"(?:echo|print)\s+\$_(?:GET|POST|REQUEST)(?![\s\S]{0,80}htmlspecialchars)"},
    {"id":"PHP_CURL_SSL_VERIFY_DISABLED","title":"PHP curl TLS Verification Disabled","vuln":"tls_bypass","sev":"Critical","langs":["php"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*0"},
    {"id":"PHP_HARDCODED_CREDENTIAL","title":"PHP Hardcoded Credential Assignment","vuln":"hardcoded_secret","sev":"High","langs":["php"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"\$\w+\s*=\s*\"[^\"]{8,}\"|\$\w+\s*=\s*'[^']{8,}'"},
    {"id":"PHP_INCLUDE_CONCAT_PATH","title":"PHP Include/Require with Concatenated Path","vuln":"path_traversal","sev":"High","langs":["php"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"(?:include|require)(?:_once)?\s*\(?\s*\"(?:/var/|/home/|/tmp/|/usr/|/etc/)[^\"]*\"\s*\.\s*[\w$]+"},

    # C/C++
    {"id":"CPP_HARDCODED_CREDENTIAL","title":"C/C++ Hardcoded Credential in String Declaration","vuln":"hardcoded_secret","sev":"High","langs":["cpp","c"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"const\s+char\s*\*?\s*\w+\s*=\s*\"[^\"]{8,}\"|char\s+\w+\[\]\s*=\s*\"[^\"]{8,}\""},
    {"id":"CPP_SQLITE3_EXEC_VARIABLE","title":"C/C++ sqlite3_exec with Variable SQL","vuln":"sql_injection","sev":"High","langs":["cpp","c"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"sqlite3_exec\s*\([^,]+,\s*\w+\s*,"},
    {"id":"CPP_SYSTEM_VARIABLE","title":"C/C++ std::system with Variable","vuln":"command_injection","sev":"Critical","langs":["cpp"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"std::system\s*\(\s*\w+\s*\)|std::system\s*\(\s*\w+\s*\+|\b_system\s*\(\s*\w+\s*\)"},
    {"id":"CPP_PATH_SNPRINTF_INTERP","title":"C/C++ Path Interpolation via snprintf/sprintf","vuln":"path_traversal","sev":"High","langs":["cpp","c"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"(?:snprintf|sprintf)\s*\([^,]+,\s*[^,]+,\s*\"[^\"]*(?:/var/|/home/|/tmp/|/usr/|/etc/)[^\"]*%s[^\"]*\"\s*,\s*\w+\s*\)"},

    # Rust
    {"id":"RUST_HARDCODED_CREDENTIAL","title":"Rust Hardcoded Credential in String Binding","vuln":"hardcoded_secret","sev":"High","langs":["rust"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"(?:let|const|static)\s+\w+\s*:\s*&str\s*=\s*\"[^\"]{8,}\"|let\s+mut\s+\w+\s*=\s*\"[^\"]{8,}\""},
    {"id":"RUST_SQL_CONCAT","title":"Rust SQL String Concatenation","vuln":"sql_injection","sev":"High","langs":["rust"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"\"[^\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^\"]*\"\s*\+\s*\w+"},
    {"id":"RUST_COMMAND_EXEC","title":"Rust Command Execution with Variable","vuln":"command_injection","sev":"Critical","langs":["rust"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"(?:std::process::Command|Command::new)\s*\([^)]*\w+"},
    {"id":"RUST_PATH_CONCAT","title":"Rust Path String Concatenation","vuln":"path_traversal","sev":"High","langs":["rust"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"\"[^\"]*(?:/var/|/home/|/tmp/|/usr/|/etc/)[^\"]*\"\s*\+\s*\w+"},
    {"id":"RUST_SQL_FORMAT","title":"Rust SQL via format! Macro","vuln":"sql_injection","sev":"High","langs":["rust"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"format!\s*\(\s*\"[^\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^\"]*\""},
    {"id":"RUST_PATH_FORMAT","title":"Rust Path via format! Macro","vuln":"path_traversal","sev":"High","langs":["rust"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"format!\s*\(\s*\"[^\"]*(?:/var/|/home/|/tmp/|/usr/|/etc/)[^\"]*\""},
    # F7: the execution-sink half of the SQL-injection class.  The two
    # rules above anchor at the BUILD site (`format!("SELECT ...")`,
    # `"..." + var`), but a query string is only executed at a rusqlite
    # call -- and the golden corpus anchors its SAST-SQLI label there
    # (`conn.prepare(&sql)`, vulnerable.rs L14), where nothing fired:
    # 114/115 with line-exact identity, the lone recorded miss.  This
    # rule matches `prepare|execute|query` called with a BORROWED
    # variable; the scan loop gates it on a file-local, one-hop proof
    # that this file BUILDS that variable with format! and a SQL
    # template, so a literal argument (the parameterised
    # `conn.prepare("... ?1")` form), a handle that is never built from
    # a SQL string, and non-SQL format! templates all stay dark.
    {"id":"RUST_SQL_SINK","title":"Rust SQL Execution of a Built Query String","vuln":"sql_injection","sev":"Critical","langs":["rust"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"\.\s*(?:prepare|execute|query)\s*\(\s*&(?P<rsx_sql_var>[A-Za-z_]\w*)"},

    # Generic / GraphQL / messaging / abuse
    {"id":"GENERIC_NOSQL_INJECTION","title":"NoSQL Injection Indicator","vuln":"nosql_injection","sev":"High","langs":["javascript","typescript","python","java","php"],"cwe":"CWE-943","owasp":"A03:2021 - Injection","pat":r"(?:\b(?:db|database|collection|collections|mongo|mongodb|mongoose)\b[^\n;]{0,120}\.(?:find|findOne|findOneAnd(?:Update|Delete)|updateOne|updateMany|deleteOne|deleteMany)\s*\(|\$(?:where|regex)\b)"},
    {"id":"GRAPHQL_INTROSPECTION_ENABLED","title":"GraphQL Introspection Exposure","vuln":"graphql_exposure","sev":"High","langs":["graphql","javascript","typescript","java","python","csharp"],"cwe":"CWE-200","owasp":"A05:2021 - Security Misconfiguration","pat":r"introspection\s*:\s*true|GraphQLPlayground|graphiql\s*:\s*true|__schema|__type"},
    {"id":"GRAPHQL_QUERY_DEPTH_MISSING","title":"GraphQL Query Depth / Complexity Limit Missing","vuln":"resource_exhaustion","sev":"High","langs":["javascript","typescript","java","python","csharp"],"cwe":"CWE-400","owasp":"A05:2021 - Security Misconfiguration","pat":r"new\s+ApolloServer\s*\(|GraphQLServer\s*\((?![\s\S]{0,300}(depthLimit|complexity|validationRules))"},
    {"id":"GRAPHQL_RESOLVER_BOLA","title":"GraphQL Resolver BOLA / IDOR Indicator","vuln":"idor","sev":"High","langs":["javascript","typescript","java","python","csharp"],"cwe":"CWE-639","owasp":"A01:2021 - Broken Access Control","pat":r"resolver|Query:\s*\{|Mutation:\s*\{|findById\s*\([^)]*(?:args\.id|id)"},
    {"id":"KAFKA_RABBITMQ_UNSAFE_DESERIALIZATION","title":"Kafka/RabbitMQ Unsafe Message Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["java","python","javascript","typescript","csharp"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"KafkaConsumer|@KafkaListener|RabbitListener|BasicConsume|JSON\.parse\s*\([^)]*message|ObjectMapper\s*\.readValue\s*\([^)]*(?:record|message|payload)"},
    {"id":"TENANT_ISOLATION_MISSING","title":"Tenant Isolation Failure Indicator","vuln":"tenant_isolation_failure","sev":"High","langs":["python","javascript","typescript","java","csharp","go","php"],"cwe":"CWE-639","owasp":"A01:2021 - Broken Access Control","pat":r"\b(?:tenantId|tenant_id|organizationId|org_id)\b"},
    {"id":"PRIVILEGE_ESCALATION_FIELD_BINDING","title":"Privilege Escalation Field Binding","vuln":"privilege_escalation","sev":"Critical","langs":["python","javascript","typescript","java","csharp","go","php"],"cwe":"CWE-269","owasp":"A01:2021 - Broken Access Control","pat":r"(?:isAdmin|role|roles|permission|permissions|privilege|is_superuser)\s*[:=]\s*(?:req\.|request\.|body|params|\$_)"},
    {"id":"WORKFLOW_APPROVAL_BYPASS","title":"Workflow / Approval Bypass Indicator","vuln":"workflow_bypass","sev":"High","langs":["python","javascript","typescript","java","csharp","go","php"],"cwe":"CWE-840","owasp":"A04:2021 - Insecure Design","pat":r"approval_required\s*[:=]\s*false|skip_approval|auto_approve|approved\s*[:=]\s*true"},
    {"id":"DUPLICATE_ACTION_RACE","title":"Duplicate Action Race Indicator","vuln":"race_condition","sev":"High","langs":["python","javascript","typescript","java","csharp","go","php"],"cwe":"CWE-362","owasp":"A04:2021 - Insecure Design","pat":r"(?:payment|transfer|coupon|redeem|invite|otp|reset)[\s\S]{0,120}(?:save|insert|update|create)(?![\s\S]{0,160}(transaction|lock|idempotency|unique))"},

    {
        "id": "MISSING_RATE_LIMIT_ENDPOINT",
        "title": "Abuse-Prone Endpoint Missing Rate-Limit Control",
        "vuln": "api_rate_limit",
        "sev": "High",
        "langs": ["python", "javascript", "typescript", "java", "csharp", "go", "php"],
        "cwe": "CWE-770",
        "owasp": "A04:2021 - Insecure Design",
        # I1 (2026-10-19, prodtest/express): "transfer" matched HTTP framing
        # headers -- lib/response.js:202/209 this.removeHeader('Transfer-
        # Encoding') and test/res.send.js:597/604 var transferEncodings = []
        # (4 rows). Transfer-Encoding is response framing, not a payment
        # endpoint; anything followed by "encod" is excluded. Real transfer
        # routes ("/wallet/transfer") keep matching.
        "pat": r"""(?i)(?:login|sign[-_]?in|otp|password[-_]?reset|reset|invite|coupon|refresh|payment|checkout|transfer(?![-_]?encod)|redeem)""",
        "remediation": BASE_REMEDIATION["api_rate_limit"],
    },

    # --- G23 coverage-audit gap fixes (2026-10-22, red-first) -------------
    # Every arm below is NON-JAVA so the OWASP Benchmark identity diff stays
    # empty by construction (benchmark fixtures are Java). Each rule carries a
    # window/context guard wired in scan_file's dispatch so literals, escaped
    # values and ownership-checked/validated flows stay dark.
    # F1 JS/TS XSS (audit: no JS/TS XSS rule existed).
    {"id":"NODE_DOM_XSS","title":"JavaScript DOM XSS via innerHTML/outerHTML/insertAdjacentHTML/document.write","vuln":"xss","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-79","owasp":"A03:2021 - Injection","pat":r"\.\s*(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\("},
    {"id":"EXPRESS_REFLECTED_XSS","title":"Express Reflected XSS via res.send/end/write","vuln":"xss","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-79","owasp":"A03:2021 - Injection","pat":r"\bres\.(?:send|end|write)\s*\("},
    # F2 C/C++ memory safety (audit: no C/C++ arm existed).
    {"id":"CPP_UNSAFE_STRING_FUNCTION","title":"C/C++ Unbounded String Function","vuln":"buffer_overflow","sev":"High","langs":["cpp","c"],"cwe":"CWE-120","owasp":"A04:2021 - Insecure Design","pat":r"\b(?:strcpy|strcat|gets|sprintf|vsprintf)\s*\("},
    {"id":"CPP_FORMAT_STRING","title":"C/C++ Format String Built from a Variable","vuln":"format_string","sev":"High","langs":["cpp","c"],"cwe":"CWE-134","owasp":"A03:2021 - Injection","pat":r"(?P<cfunc>\b(?:printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf))\s*\("},
    {"id":"CPP_USE_AFTER_FREE","title":"C/C++ Use After Free","vuln":"use_after_free","sev":"High","langs":["cpp","c"],"cwe":"CWE-416","owasp":"A04:2021 - Insecure Design","pat":r"\bfree\s*\(\s*(?P<uaf_ptr>\w+)\s*\)"},
    # F3 Generic REST IDOR as a FINDING (audit: only summary-level/GraphQL
    # before). Ownership-gated so a handler that checks the object's owner in
    # the same function stays dark.
    {"id":"NODE_IDOR_OBJECT_FETCH","title":"Node.js Object Fetch by Request-Supplied ID Without Ownership Check","vuln":"idor","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-639","owasp":"A01:2021 - Broken Access Control","pat":r"\.\s*(?:findByPk|findById|getById|getByPk|findByPkOr404)\s*\("},
    {"id":"PY_IDOR_OBJECT_FETCH","title":"Python ORM Object Fetch by Request-Supplied ID Without Ownership Check","vuln":"idor","sev":"High","langs":["python"],"cwe":"CWE-639","owasp":"A01:2021 - Broken Access Control","pat":r"\.\s*objects\s*\.\s*(?:get|filter)\s*\(|(?<![A-Za-z0-9_])get_object_or_404\s*\("},
    # F4 session fixation + cookie flags (audit: finding-level thin).
    {"id":"FLASK_SESSION_FIXATION","title":"Flask-Login login_user Without Session Key Rotation","vuln":"session_fixation","sev":"Medium","langs":["python"],"cwe":"CWE-384","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"(?<![A-Za-z0-9_])login_user\s*\("},
    {"id":"DJANGO_SESSION_COOKIE_INSECURE","title":"Django Session Cookie Security Flag Disabled","vuln":"insecure_cookie_secure_flag","sev":"Medium","langs":["python"],"cwe":"CWE-614","owasp":"A05:2021 - Security Misconfiguration","pat":r"\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b"},
    {"id":"EXPRESS_COOKIE_MISSING_SECURE","title":"Express Cookie Missing secure Flag","vuln":"insecure_cookie_secure_flag","sev":"Medium","langs":["javascript","typescript"],"cwe":"CWE-614","owasp":"A05:2021 - Security Misconfiguration","pat":r"\bres\.cookie\s*\("},
    # P4 cookie arms (2026-10-23): Go and .NET set cookies through named
    # struct/options fields, so the missing-option shape is the same one the
    # Express gate already proves: a known cookie-setting call whose option
    # block lacks the flag, not a blanket report of every SetCookie.
    {"id":"GO_COOKIE_MISSING_SECURE","title":"Go Cookie Missing Secure Flag","vuln":"insecure_cookie_secure_flag","sev":"Medium","langs":["go"],"cwe":"CWE-614","owasp":"A05:2021 - Security Misconfiguration","pat":r"\bhttp\.SetCookie\s*\("},
    {"id":"GO_COOKIE_MISSING_HTTPONLY","title":"Go Cookie Missing HttpOnly Flag","vuln":"insecure_cookie_httponly_flag","sev":"Medium","langs":["go"],"cwe":"CWE-1004","owasp":"A04:2021 - Insecure Design","pat":r"\bhttp\.SetCookie\s*\("},
    {"id":"DOTNET_COOKIE_MISSING_SECURE","title":".NET Cookie Missing Secure Flag","vuln":"insecure_cookie_secure_flag","sev":"Medium","langs":["csharp"],"cwe":"CWE-614","owasp":"A05:2021 - Security Misconfiguration","pat":r"\bResponse\s*\.\s*Cookies\s*\.\s*(?:Append|Add)\s*\("},
    {"id":"DOTNET_COOKIE_MISSING_HTTPONLY","title":".NET Cookie Missing HttpOnly Flag","vuln":"insecure_cookie_httponly_flag","sev":"Medium","langs":["csharp"],"cwe":"CWE-1004","owasp":"A04:2021 - Insecure Design","pat":r"\bResponse\s*\.\s*Cookies\s*\.\s*(?:Append|Add)\s*\("},
    # F5 single-arm fill-ins (only provable shapes).
    {"id":"PY_XML_ENTITIES","title":"Python lxml XML External Entity Risk","vuln":"xxe","sev":"High","langs":["python"],"cwe":"CWE-611","owasp":"A05:2021 - Security Misconfiguration","pat":r"\betree\.(?:parse|fromstring|XML)\s*\(|\bXMLParser\s*\("},
    {"id":"PHP_XXE_LIBXML","title":"PHP libxml XML External Entity Risk","vuln":"xxe","sev":"High","langs":["php"],"cwe":"CWE-611","owasp":"A05:2021 - Security Misconfiguration","pat":r"(?<![A-Za-z0-9_])(?:simplexml_load_(?:string|file)|loadXML|libxml_disable_entity_loader)\s*\("},
    {"id":"PY_REDOS_NESTED_QUANTIFIER","title":"Python ReDoS Nested Quantifier Regex","vuln":"redos","sev":"Medium","langs":["python"],"cwe":"CWE-1333","owasp":"A03:2021 - Injection","pat":r"\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn)\s*\("},
    {"id":"PHP_REDOS_NESTED_QUANTIFIER","title":"PHP preg ReDoS Nested Quantifier Regex","vuln":"redos","sev":"Medium","langs":["php"],"cwe":"CWE-1333","owasp":"A03:2021 - Injection","pat":r"(?<![A-Za-z0-9_])preg_(?:match|match_all|replace|split|grep)\s*\("},
    {"id":"PY_LOG_INJECTION","title":"Python Logging of Untrusted Request Data","vuln":"log_injection","sev":"Medium","langs":["python"],"cwe":"CWE-117","owasp":"A09:2021 - Security Logging and Monitoring Failures","pat":r"(?i)(?:\blog(?:ging)?|\blogger|app\.logger|_logger)\s*\.\s*(?:info|warning|error|debug|exception|critical|log)\s*\([^)]*(?<![A-Za-z0-9_])(?:request|req)\."},
    {"id":"PHP_LOG_INJECTION","title":"PHP Logging of Untrusted Request Data","vuln":"log_injection","sev":"Medium","langs":["php"],"cwe":"CWE-117","owasp":"A09:2021 - Security Logging and Monitoring Failures","pat":r"(?<![A-Za-z0-9_])(?:error_log|syslog|trigger_error)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)"},
    {"id":"HOST_HEADER_INJECTION","title":"Host Header Used to Construct URL or Email","vuln":"host_header_injection","sev":"Medium","langs":["php","python"],"cwe":"CWE-644","owasp":"A03:2021 - Injection","pat":r"\$_SERVER\s*\[\s*[\"']HTTP_HOST[\"']\s*\]|request\.headers\s*\[\s*[\"']Host[\"']\s*\]|request\.headers\.get\s*\(\s*[\"']Host[\"']"},
    {"id":"NODE_WEBSOCKET_SINK","title":"Node.js WebSocket Message Flowing to Dangerous Sink","vuln":"code_injection","sev":"High","langs":["javascript","typescript"],"cwe":"CWE-94","owasp":"A03:2021 - Injection","pat":r"\.\s*on\s*\(\s*[\"'](?:message|data)[\"']"},
    {"id":"PY_TAR_EXTRACTALL","title":"Python tarfile Extract Without Member Validation","vuln":"zipslip","sev":"High","langs":["python"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"\.extractall\s*\("},

    # Rate-limit detection is validated by _is_rate_limit_endpoint_match().
    # The regex only locates abuse-prone endpoint strings; the validator requires
    # server-side route evidence so frontend navigation/API references do not fire.
]

# Backward-compatible existing rules retained. These are intentionally simple.
REGEX_RULES: list[dict] = [
    # I3 (2026-10-19, prodtest/ethernaut): compiled case-SENSITIVE. With
    # IGNORECASE the base58 CID QmTzWboptc2WjGQH4ShcN4XAkiaskScQ7fFtfgvMsW
    # inside forge ABIs matched "AkiaskScQ7fFtfgvMsW" as an AWS key (2 rows).
    # Real AWS access key IDs are uppercase AKIA/ASIA + 16 uppercase
    # alphanumerics; base58/base64/CID content must not match.
    {"id":"AWS_ACCESS_KEY","name":"AWS Access Key","pattern":re.compile(r"AKIA[0-9A-Z]{16}"),"vuln_type":"hardcoded_secret","note":"AWS access key ID detected in source code.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"GITHUB_TOKEN","name":"GitHub Token","pattern":re.compile(r"ghp_[A-Za-z0-9]{36}", _F),"vuln_type":"hardcoded_secret","note":"GitHub personal access token detected in source code.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"GENERIC_API_KEY_PASSWORD","name":"Generic API Key/Password","pattern":re.compile(r'(?:api[_-]?key|api[_-]?token|secret[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|pwd)\s*[:=]\s*(?P<q>["\'])(?P<credval>[A-Za-z0-9@#$%^&+=!_.\-/]{8,})(?P=q)', _F),"vuln_type":"hardcoded_secret","note":"Possible hardcoded credential or API key.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    # G-036b: the sites that actually *enforce* a secret were never reported.
    # The assignment rules above catch `KEY = "..."`, but the seven checks that
    # return 401 - `if token != "sk-mock-key"`, `if api_key != "foobar"`,
    # `if api_key != "bar"` - are comparisons, not assignments, so the whole
    # authorization gate of every mock endpoint was invisible. Comparing a
    # credential-named operand to a committed literal is CWE-798 whether the
    # literal looks like a placeholder or not: the structure is the defect.
    # B7b (2026-10-16, Open-Assistant): two boundary defects in one
    # pattern.  (1) The noun sat behind a ``\b`` that cannot fire between
    # ``_`` and a letter, so the canonical shapes
    # ``access_token == "literal"`` and ``user_password == "literal"``
    # could NEVER match -- a detection failure, pinned by the two FN-fix
    # controls.  The prefix boundary is now a negative lookbehind that
    # admits ``_``/``-``/digit before the noun.  (2) The noun carried an
    # unrestricted ``[\w]*`` suffix, so OA's
    # ``args.tokenizer_type == "FalconTokenizer"`` (x5) matched -- a
    # tokenizer TYPE label is not a credential.  The suffix must now
    # start with ``_``/``-``/digit, keeping ``password_hash``/``api_key2```
    # firing while plural containers (``tokens == "x"``,
    # ``secrets == "x"``) stop matching -- consistent with the
    # leaf-scoped rationale that already excludes containers.
    {"id":"HARDCODED_CREDENTIAL_COMPARISON","name":"Hardcoded credential authorization comparison","pattern":re.compile(r"\b(?:if|elif|while)\s+(?:not\s+)?[\w.\[\]]*(?<![A-Za-z0-9])(?:api[_-]?key|apikey|access[_-]?key|password|passwd|pwd|passphrase|secret|token|credential)(?:[_\-0-9][\w]*)?\s*(?:==|!=|not\s+in)\s*[\"'](?P<credval>[^\"'\s]{1,128})[\"']", _F),"vuln_type":"hardcoded_secret","note":"A credential-named value is compared against a literal, so the secret is committed to source and doubles as the authorization check.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"PRIVATE_KEY_HEADER","name":"Private Key Header","pattern":re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", _F),"vuln_type":"hardcoded_secret","note":"Private key material in source code.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    # 2026-10-21 prodtest/pygoat: the qualified `hashlib.md5(` arm missed
    # ``from hashlib import md5; md5(password.encode())`` (mitre.py:161, CNAP
    # CRYPTO-WEAK-003 TP). The trailing bare-call arm matches it; the
    # _aliased_hashlib_match gate below keeps bare md5()/sha1() calls quiet
    # unless the file imports that name from hashlib.
    {"id":"MD5_USAGE","name":"MD5 Usage","pattern":re.compile(r"hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']MD5|MD5CryptoServiceProvider|crypto\.createHash\s*\(\s*[\"']md5|(?<![\w.])md5\s*\(", _F),"vuln_type":"weak_crypto","note":"MD5 is cryptographically broken.","severity":"High","cwe":"CWE-327","owasp":"A02:2021 - Cryptographic Failures"},
    {"id":"SHA1_USAGE","name":"SHA-1 Usage","pattern":re.compile(r"hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1|SHA1CryptoServiceProvider|crypto\.createHash\s*\(\s*[\"']sha1|(?<![\w.])sha1\s*\(", _F),"vuln_type":"weak_crypto","note":"SHA-1 is deprecated for cryptographic use.","severity":"High","cwe":"CWE-327","owasp":"A02:2021 - Cryptographic Failures"},
    {"id":"FLASK_DEBUG","name":"Flask Debug Mode","pattern":re.compile(r"app\.run\s*\([^)]*debug\s*=\s*True", _F),"vuln_type":"debug_exposure","note":"Flask debug=True exposes interactive debugger in production.","severity":"High","cwe":"CWE-215","owasp":"A05:2021 - Security Misconfiguration"},
    {"id":"SUBPROCESS_SHELL_TRUE","name":"subprocess shell=True","pattern":re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True", _F),"vuln_type":"command_injection","note":"subprocess with shell=True enables shell injection.","severity":"Critical","cwe":"CWE-78","owasp":"A03:2021 - Injection"},
    {"id":"OS_SYSTEM","name":"os.system Call","pattern":re.compile(r"os\.system\s*\(", _F),"vuln_type":"command_injection","note":"os.system executes shell commands.","severity":"Critical","cwe":"CWE-78","owasp":"A03:2021 - Injection"},
    # A1 (transformers validation): 2822/2822 matches in transformers were
    # receiver-form nn.Module/evaluator calls (``model.eval()``, a boolean-mode
    # toggle that does not execute input). Only a *bare* eval call -- or eval
    # hosted on an explicit dynamic-evaluation namespace -- executes code.
    # Precedent: PYTHON_EXEC_CALL's ``(?<![.\w])exec\s*\(`` keeps the same
    # receiver-form exclusion. e2e keeps server.js's bare ``eval(``; the corpus
    # keeps PHP ``eval($code)``.
    {"id":"EVAL_CALL","name":"eval() Call","pattern":re.compile(r"(?<![\w.])eval\s*\(|(?<=window\.)eval\s*\(|(?<=globalThis\.)eval\s*\(|(?<=builtins\.)eval\s*\(", _F),"vuln_type":"code_injection","note":"eval() executes arbitrary code.","severity":"Critical","cwe":"CWE-94","owasp":"A03:2021 - Injection"},
    {"id":"PYTHON_EXEC_CALL","name":"Python exec() Call","pattern":re.compile(r"(?<![.\w])exec\s*\(", _F),"vuln_type":"code_injection","note":"Python exec() executes arbitrary code.","severity":"Critical","cwe":"CWE-94","owasp":"A03:2021 - Injection","languages":{"python"}},
    {"id":"PYTHON_PICKLE_LOADS","name":"Python pickle.loads Insecure Deserialization","pattern":re.compile(r"pickle\.loads\s*\(", _F),"vuln_type":"insecure_deserialization","note":"pickle.loads deserializes untrusted data.","severity":"Critical","cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","languages":{"python"}},
    {"id":"PYTHON_PICKLE_LOAD","name":"Python pickle.load Insecure Deserialization","pattern":re.compile(r"pickle\.load\s*\(", _F),"vuln_type":"insecure_deserialization","note":"pickle.load deserializes untrusted data from a file.","severity":"Critical","cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","languages":{"python"}},
    # Phase 6 HF loading-pattern technique: torch.load unpickles the checkpoint,
    # so without weights_only=True a tampered weights file is arbitrary code
    # execution. The kill is a tempered negative lookahead: within 300 chars
    # that NEVER cross another torch.load( (the next call's guard cannot leak
    # backwards), weights_only=True keeps the finding. Finding-only.
    {"id":"PYTHON_TORCH_LOAD_UNSAFE","name":"Python torch.load Without weights_only Guard","pattern":re.compile(r"torch\.load\s*\((?!(?:(?!torch\.load\s*\()[\s\S]){0,300}weights_only\s*=\s*True)", _F),"vuln_type":"insecure_deserialization","note":"torch.load unpickles the checkpoint; without weights_only=True a tampered file executes arbitrary code on load.","severity":"Critical","cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","languages":{"python"}},
    # Phase 6: trust_remote_code=True executes modeling code shipped by the model
    # repository instead of the installed library -- code from an external
    # control sphere. trust_remote_code=False never matches; indirection is an
    # honest recall gap rather than a guess.
    {"id":"PYTHON_TRANSFORMERS_REMOTE_CODE","name":"transformers trust_remote_code=True","pattern":re.compile(r"trust_remote_code\s*=\s*True", _F),"vuln_type":"code_injection","note":"trust_remote_code=True executes modeling code from the model repository instead of the installed library.","severity":"High","cwe":"CWE-94","owasp":"A08:2021 - Software and Data Integrity Failures","languages":{"python"}},
    {"id":"PYTHON_RENDER_STRING","name":"Python Flask render_string Template Injection","pattern":re.compile(r"render_string\s*\(", _F),"vuln_type":"template_injection","note":"render_string with user-controlled template enables SSTI.","severity":"Critical","cwe":"CWE-94","owasp":"A03:2021 - Injection","languages":{"python"}},
]


# Context-only heuristic rules are intentionally disabled from canonical SAST promotion.
# They are handled by framework/taint engines when sufficient context exists.
DISABLED_CONTEXT_ONLY_RULES = {"GRAPHQL_RESOLVER_BOLA", "DUPLICATE_ACTION_RACE"}

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

BIG4_REMEDIATION_BY_RULE = {
    "SPRING_ACTUATOR_EXPOSE_ALL": ["Do not expose all actuator endpoints in production.", "Set management.endpoints.web.exposure.include to a minimal allow-list such as health/info only.", "Protect actuator endpoints with Spring Security and network ACLs.", "Disable sensitive endpoints such as env, beans, heapdump, threaddump, mappings and configprops."],
    "SPRING_SECURITY_CSRF_DISABLED": ["Do not globally disable CSRF protection for browser-based sessions.", "Enable CSRF for state-changing endpoints or use stateless token-based APIs with explicit compensating controls.", "Avoid broad anyRequest().permitAll() and require authenticated authorization rules by default.", "Add security tests for unauthenticated state-changing requests."],
    "SPRING_SPEL_INJECTION": ["Never evaluate user-controlled input with SpEL parseExpression().", "Replace dynamic expressions with allow-listed operations or server-side enum choices.", "Use SimpleEvaluationContext where expression evaluation is unavoidable.", "Reject expressions containing type references, method calls, constructors or bean references."],
    "SPRING_MASS_ASSIGNMENT_ENTITY_BINDING": ["Bind requests to explicit DTOs rather than JPA/domain entities.", "Use allow-listed fields and ignore role, tenantId, isAdmin, status, balance and permission fields.", "Validate with @Valid/@Validated and enforce server-side authorization after binding."],
    "JAVA_TEMPLATE_INJECTION": ["Do not treat user input as template source or template name.", "Use fixed server-side template names and pass user input only as escaped model data.", "Disable unrestricted template resolvers and expression utilities."],
    "JAVA_TLS_TRUST_BYPASS": ["Remove permissive TrustManager and HostnameVerifier implementations.", "Use the default JVM trust store or managed certificate pinning.", "Fail closed on certificate and hostname validation errors."],
    "DOTNET_CERT_VALIDATION_BYPASS": ["Remove DangerousAcceptAnyServerCertificateValidator and callbacks returning true.", "Use default HttpClient certificate validation and trusted roots.", "Pin certificates only with explicit rotation procedures."],
    "DOTNET_LOG_INJECTION": ["Use structured logging placeholders instead of concatenating raw user input.", "Normalize CR/LF and control characters before logging.", "Do not log secrets, tokens, cookies or raw request bodies."],
    "NODE_UNSAFE_EVAL_VM_FUNCTION": ["Remove eval(), vm execution and new Function() for untrusted input.", "Use schema-validated data, safe interpreters or fixed allow-listed commands.", "Apply CSP and runtime sandboxing where dynamic execution cannot be avoided."],
    "NODE_SERIALIZE_UNSERIALIZE": ["Do not unserialize untrusted node-serialize payloads.", "Use JSON.parse for data-only payloads and reject functions/prototypes.", "Apply integrity checks and strict type allow-lists."],
    "NODE_JSYAML_UNSAFE_LOAD": ["Use safe schema loading for YAML and reject custom tags/types.", "Do not parse untrusted YAML with unsafe constructors.", "Prefer JSON for external data interchange."],
    "GO_SHARED_MAP_RACE": ["Protect shared maps/slices using sync.Mutex, sync.RWMutex, channels or sync.Map.", "Run go test -race in CI.", "Make check-and-act workflows atomic with transactions or locks."],
    "GO_GOB_DECODE": ["Do not gob-decode untrusted network or message-bus payloads.", "Use JSON/protobuf with explicit schemas and validation.", "Authenticate and integrity-protect serialized messages."],
    "GENERIC_ZIPSLIP": ["Canonicalize archive entry paths before extraction.", "Reject absolute paths and entries containing .. segments.", "Verify the resolved destination remains under the intended extraction directory."],
    "GENERIC_TOCTOU_RACE": ["Avoid check-then-use filesystem and workflow patterns.", "Use atomic file operations, transactions or locks.", "Re-check authorization and object state inside the final transaction."],
}

BIG4_RULE_PATCHES = {
    "SPRING_SPEL_INJECTION": {"pat": r"parseExpression\s*\([^)]*(?:request|getParameter|@RequestParam|@PathVariable|param|input)|SpelExpressionParser[\s\S]{0,240}parseExpression\s*\(", "evidence_pat": r"parseExpression\s*\("},
    "SPRING_ACTUATOR_EXPOSE_ALL": {"pat": r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*[\"']?\*[\"']?|exposure:\s*\n\s*include:\s*[\"']?\*[\"']?", "evidence_pat": r"include\s*[:=]\s*[\"']?\*[\"']?"},
    "JAVA_SNAKEYAML_UNSAFE_LOAD": {"pat": r"(?:new\s+Yaml\s*\([^)]*\)|Yaml\s+\w+\s*=\s*new\s+Yaml\s*\([^)]*\))[\s\S]{0,240}\.load\s*\(|\.load\s*\([^)]*(?:request|getParameter|input|payload|body)"},
    "JAVA_XSTREAM_DESERIALIZATION": {"pat": r"new\s+XStream\s*\(|\.fromXML\s*\([^)]*(?:request|getParameter|input|payload|body)?"},
    "JAVA_JACKSON_DEFAULT_TYPING": {"pat": r"enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|DefaultTyping\.|@JsonTypeInfo|ObjectMapper[\s\S]{0,200}enableDefaultTyping"},
    "DOTNET_DATACONTRACT_DESERIALIZER": {"pat": r"(?:DataContractSerializer|NetDataContractSerializer)\s*\(|\.ReadObject\s*\([^)]*(?:Request|Body|Stream|input|payload)?"},
    "DOTNET_ZIPSLIP_EXTRACT": {"pat": r"ZipFile\.ExtractToDirectory\s*\(|ZipArchive[\s\S]{0,300}(?:ExtractToFile|FullName)"},
    "DOTNET_LOG_INJECTION": {"sev":"High", "pat": r"(?:ILogger|_logger)\.(?:Information|Error|Warning|Debug|LogInformation|LogError|LogWarning)\s*\([^)]*(?:Request|Query|Form|Headers|userInput|returnUrl|User\.Identity)"},
    "NODE_UNSAFE_EVAL_VM_FUNCTION": {"pat": r"\beval\s*\([^)]*(?:req\.|request|body|query|params)?|new\s+Function\s*\([^)]*(?:req\.|request|body|query|params)?|vm\.runIn(?:This|New)Context\s*\("},
    "NODE_JSYAML_UNSAFE_LOAD": {"pat": r"(?:jsyaml|js_yaml|yaml)\.load\s*\([^)]*(?:req\.|request|body|query|payload)?"},
    "GO_GOB_DECODE": {"pat": r"gob\.NewDecoder\s*\([^)]*(?:r\.Body|conn|msg|payload|reader)?[\s\S]{0,200}\.Decode\s*\("},
    "GO_SHARED_MAP_RACE": {"pat": r"var\s+\w+\s*=\s*map\[|var\s+\w+\s+map\[|go\s+func\s*\([\s\S]{0,300}\w+\s*\[[^\]]+\]\s*="},
    "GRAPHQL_QUERY_DEPTH_MISSING": {"pat": r"new\s+ApolloServer\s*\((?![\s\S]{0,400}(depthLimit|queryComplexity|complexity|validationRules))|GraphQLServer\s*\((?![\s\S]{0,400}(depthLimit|queryComplexity|complexity|validationRules))"},
}
for _rule in ENTERPRISE_RULES:
    _patch = BIG4_RULE_PATCHES.get(_rule.get("id"))
    if _patch:
        _rule.update(_patch)
    if _rule.get("id") in BIG4_REMEDIATION_BY_RULE:
        _rule["remediation"] = BIG4_REMEDIATION_BY_RULE[_rule["id"]]

_existing_rule_ids = {r.get("id") for r in ENTERPRISE_RULES}
_EXTRA_BIG4_RULES = [
    {"id":"JAVA_TRUSTMANAGER_EMPTY_METHOD","title":"Java TrustManager Empty Certificate Validation","vuln":"tls_bypass","sev":"Critical","langs":["java"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}","remediation":BIG4_REMEDIATION_BY_RULE.get("JAVA_TLS_TRUST_BYPASS")},
    {"id":"JAVA_SPRING_QUERY_ANNOTATION_CONCAT","title":"Spring Data @Query Concatenation Injection","vuln":"orm_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"@Query\s*\(\s*(?:value\s*=\s*)?[\"'][^\"']*[\"']\s*\+|@Query[\s\S]{0,160}(?:nativeQuery\s*=\s*true)[\s\S]{0,160}\+"},
    {"id":"JAVA_THYMELEAF_FREEMARKER_VELOCITY_INJECTION","title":"Spring Template Injection: Thymeleaf/Freemarker/Velocity","vuln":"template_injection","sev":"High","langs":["java"],"cwe":"CWE-94","owasp":"A03:2021 - Injection","pat":r"(?:TemplateEngine|SpringTemplateEngine|FreeMarkerTemplateUtils|VelocityEngine|StringTemplateResolver)[\s\S]{0,240}(?:process|evaluate|mergeTemplate|setTemplateMode|setTemplateResolver)\s*\([^)]*(?:request|getParameter|param|input|body)?","remediation":BIG4_REMEDIATION_BY_RULE.get("JAVA_TEMPLATE_INJECTION")},
    {"id":"DOTNET_HTTPCLIENT_CERT_CALLBACK_TRUE","title":".NET HttpClient Certificate Validation Bypass","vuln":"tls_bypass","sev":"Critical","langs":["csharp"],"cwe":"CWE-295","owasp":"A02:2021 - Cryptographic Failures","pat":r"ServerCertificateCustomValidationCallback\s*=\s*(?:HttpClientHandler\.)?DangerousAcceptAnyServerCertificateValidator|ServerCertificateCustomValidationCallback\s*=\s*[^;]*=>\s*true","remediation":BIG4_REMEDIATION_BY_RULE.get("DOTNET_CERT_VALIDATION_BYPASS")},
    {"id":"GO_JSON_UNMARSHAL_INTERFACE","title":"Go json.Unmarshal into interface{} / any","vuln":"insecure_deserialization","sev":"High","langs":["go"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"var\s+\w+\s+(?:interface\s*\{\s*\}|any)\s*\n[\s\S]{0,160}json\.Unmarshal\s*\(|json\.Unmarshal\s*\([^,]+,\s*&\w+\s*\)[\s\S]{0,120}(?:map\[string\]interface|interface\s*\{\s*\}|any)"},
    {"id":"GENERIC_ZIPSLIP","title":"Generic ZipSlip Archive Extraction","vuln":"zipslip","sev":"High","langs":["java","csharp","javascript","typescript","python","go","php"],"cwe":"CWE-22","owasp":"A01:2021 - Broken Access Control","pat":r"(?:ZipEntry|getNextEntry|ZipArchive|adm-zip|unzipper|zipfile|archive/zip)[\s\S]{0,180}(?:extractToDirectory|extractToFile|extractAll|extract\s*\(|writeFile(?:Sync)?\s*\(|createWriteStream\s*\(|FileOutputStream\s*\(|OpenFile\s*\()","remediation":BIG4_REMEDIATION_BY_RULE.get("GENERIC_ZIPSLIP")},
]
for _r in _EXTRA_BIG4_RULES:
    if _r["id"] not in _existing_rule_ids:
        ENTERPRISE_RULES.append(_r)
        _existing_rule_ids.add(_r["id"])
# ---- end Big4 enterprise gap patch ----

COMPILED_ENTERPRISE_RULES = [
    {**r, "pattern": re.compile(r["pat"], _F)}
    for r in ENTERPRISE_RULES
    if r.get("id") not in DISABLED_CONTEXT_ONLY_RULES
]


def _skip(path: Path) -> bool:
    # Normalize every path component so excluded directories such as
    # Node_Modules / BUILD / Venv cannot bypass the exclusion policy.
    excluded_files = {str(name).lower() for name in EXCLUDED_FILES}
    excluded_dirs = {str(name).lower() for name in EXCLUDED_DIRS}
    if (
        path.name.lower() in excluded_files
        or any(str(part).lower() in excluded_dirs for part in path.parts)
        # I19 (2026-10-26, aclean): a scanner-result JSON export inside the
        # tree is tool output, not source. 98 rows on the aclean corpus came
        # from reading one export's own evidence back as code.
        or _is_scanner_result_json(path)
    ):
        return True
    return False


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


def _is_scanner_result_json(path: Path) -> bool:
    """True when the file is a SECURITY-SCANNER RESULT export (JSON).

    Third-party scanner exports embed evidence from ELSEWHERE in the repo, so
    findings read off them double-count real findings and invent new ones. The
    aclean corpus carried ``RBI7SASTSBOMSCA-result.json``: 98 rows whose
    snippets are that export's own text, matched again as if it were source.

    Detection is by CONTENT -- the report schema's own markers
    (``metadata.tool`` + ``total_findings`` + a ``findings`` list whose members
    carry ``rule_id``) -- and never by filename, so an application JSON that
    happens to hold a ``findings`` array without the report envelope is still
    scanned. The header read is bounded like the XML variant below.
    """
    if path.suffix.lower() != ".json":
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    # The report envelope: a metadata block naming the tool, a total_findings
    # counter beside it, and a findings array. Requiring BOTH the counter and
    # the tool name keeps a config file that merely mentions "findings" clean.
    if '"total_findings"' not in head and '"scan_date"' not in head:
        return False
    if '"tool"' not in head:
        return False
    if '"findings"' not in head and '"secret-id"' not in head:
        return False
    # Corroborate the findings-array member shape: rule_id is the one key every
    # finding carries and no benign config file does.
    return '"rule_id"' in head


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
        php_files = list(Path(target).rglob("*.php"))
    except OSError:
        php_files = []
    for fp in php_files:
        if _skip(fp):
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
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
_PHP_SINK_CATEGORY = {
    "PHP_SQL_INTERMEDIATE_QUERY": "sql",
    "JAVA_JDBC_SQL_INTERMEDIATE_QUERY": "sql",
    "JAVA_JDBC_SQL_PREPARED_CONCAT": "sql",
    "PHP_XSS_TAINTED_ECHO": "xss",
    "PHP_PATH_USER_INPUT_VAR": "file",
    "PHP_OPEN_REDIRECT_HEADER": "redirect",
    "PHP_CMD_INJECTION_INTERMEDIATE": "command",
}


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
    if _CAMEL_PLACEHOLDER_PREFIX.match(raw_value):
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
        # it is not reported.
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
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
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
        for match in rule["pattern"].finditer(source):
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
        for match in rule["pattern"].finditer(source):
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
    all_files = [f for f in target.rglob("*") if f.is_file() and _should_scan(f)]
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
                for _jp in target.rglob("*.java"):
                    if any(seg in {".git", "target", "build", "__pycache__",
                                   "node_modules", "test", "tests"}
                           for seg in _jp.parts):
                        continue
                    try:
                        _src = _jp.read_text(encoding="utf-8", errors="replace")
                    except OSError:
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


