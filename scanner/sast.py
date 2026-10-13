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

SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".scala", ".go",
    ".rb", ".php", ".cs", ".vb", ".cpp", ".c", ".h", ".hpp", ".rs", ".sh",
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
}

# qbom.json added with the Quantum BOM artifact (CERT-In v2.0 Table 8). The handoff
# lists this exact hazard: a new artifact filename must be excluded or the scanner
# reads its own output back as scanned input.
EXCLUDED_DIRS = {
    ".git", ".svn", "node_modules", "__pycache__", ".tox", "venv", ".venv",
    "env", ".env", "dist", "build", ".cache", "vendor", "third_party", "migrations",
    "reports", "artifacts", "output", "outputs", "coverage", ".pytest_cache",
}

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".scala": "scala", ".go": "go", ".php": "php",
    ".cs": "csharp", ".vb": "vbnet", ".xml": "xml", ".properties": "properties",
    ".rs": "rust",
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
    "dangerous_reflection": ["Avoid bypassing access checks through reflection.", "Do not call setAccessible(true) on user-influenced classes or members.", "Use explicit allow-lists for reflective operations."],
    "template_injection": ["Do not evaluate user-controlled templates.", "Use safe template contexts and escaping.", "Separate template names from template content."],
    "graphql_exposure": ["Disable GraphQL introspection in production unless explicitly required.", "Require authentication and authorization on GraphQL endpoints.", "Add query depth, complexity and rate limits."],
    "resource_exhaustion": ["Set explicit request/body/upload limits and operation timeouts at the server boundary.", "For GraphQL or expensive queries, enforce depth/complexity limits before execution.", "Stream large inputs where possible and rate-limit expensive operations; add tests for oversized and repeated requests."],
    "race_condition": ["Protect shared mutable state with locks/transactions.", "Use idempotency keys for duplicate actions.", "Make check-and-act operations atomic."],
    "api_rate_limit": ["Add server-side per-account/per-IP/per-tenant limits appropriate to the endpoint.", "Add progressive backoff for login/OTP/reset and idempotency keys for payment or other duplicate-sensitive actions.", "Return 429 on throttling, emit abuse metrics, and add burst/replay regression tests."],
}

def _priority(sev: str) -> str:
    return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(sev, "P3")

ENTERPRISE_RULES: list[dict] = [
    {"id":"NODE_CHILD_PROCESS_EXEC","title":"Node.js child_process.exec Command Execution","vuln":"command_injection","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"\bchild_process\.(?:exec|execSync|execFile|execFileSync)\s*\("},
    {"id":"NODE_IMPORTED_CHILD_PROCESS_EXEC","title":"Node.js imported child_process.exec Command Execution","vuln":"command_injection","sev":"Critical","langs":["javascript","typescript"],"cwe":"CWE-78","owasp":"A03:2021 - Injection","pat":r"(?<![.\w])(?:exec|execSync|execFile|execFileSync)\s*\("},
    # Java / Spring Boot
    {"id":"JAVA_OBJECTINPUTSTREAM_DESERIALIZATION","title":"Java ObjectInputStream Insecure Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"new\s+ObjectInputStream\s*\(|\.readObject\s*\("},
    {"id":"JAVA_JACKSON_DEFAULT_TYPING","title":"Jackson Unsafe Default Typing","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|DefaultTyping\.|@JsonTypeInfo"},
    {"id":"JAVA_SNAKEYAML_UNSAFE_LOAD","title":"SnakeYAML Unsafe Load","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"new\s+Yaml\s*\([^)]*\)\s*\.load\s*\(|Yaml\s+\w+\s*=\s*new\s+Yaml\s*\([^)]*\)"},
    {"id":"JAVA_XSTREAM_DESERIALIZATION","title":"XStream Insecure Deserialization","vuln":"insecure_deserialization","sev":"Critical","langs":["java"],"cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","pat":r"new\s+XStream\s*\(|\.fromXML\s*\("},
    {"id":"JAVA_JNDI_LOG4SHELL_LOOKUP","title":"JNDI / Log4Shell-style Lookup Pattern","vuln":"jndi_injection","sev":"Critical","langs":["java","properties","xml","yaml"],"cwe":"CWE-917","owasp":"A03:2021 - Injection","pat":r"\$\{\s*jndi\s*:\s*(?:ldap|rmi|dns|iiop)://|InitialContext\s*\(|\.lookup\s*\("},
    {"id":"JAVA_JDBC_SQL_CONCAT","title":"JDBC SQL Concatenation","vuln":"sql_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"(?:createStatement\s*\(\s*\)|prepareStatement\s*\(\s*\"[^\"]*\"\s*\+|executeQuery\s*\(\s*\"[^\"]*\"\s*\+)"},
    {"id":"JAVA_HQL_JPQL_INJECTION","title":"Hibernate HQL / JPQL Injection","vuln":"orm_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"createQuery\s*\(\s*\"[^\"]*(?:from|select|where)[^\"]*\"\s*\+|@Query\s*\(\s*\"[^\"]*\"\s*\+"},
    {"id":"JAVA_JOOQ_RAW_SQL","title":"jOOQ Raw SQL Injection Indicator","vuln":"orm_injection","sev":"High","langs":["java"],"cwe":"CWE-89","owasp":"A03:2021 - Injection","pat":r"DSL\.query\s*\(\s*\"[^\"]*\"\s*\+|fetch\s*\(\s*\"[^\"]*\"\s*\+"},
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
    {"id":"DOTNET_HARDCODED_CREDENTIAL","title":".NET Hardcoded Credential in String Declaration","vuln":"hardcoded_secret","sev":"High","langs":["csharp"],"cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures","pat":r"(?:string|var|const\s+string)\s+\w+\s*=\s*\"[^\"]{8,}\""},
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
        "pat": r"""(?i)(?:login|sign[-_]?in|otp|password[-_]?reset|reset|invite|coupon|refresh|payment|checkout|transfer|redeem)""",
        "remediation": BASE_REMEDIATION["api_rate_limit"],
    },
    # Rate-limit detection is validated by _is_rate_limit_endpoint_match().
    # The regex only locates abuse-prone endpoint strings; the validator requires
    # server-side route evidence so frontend navigation/API references do not fire.
]

# Backward-compatible existing rules retained. These are intentionally simple.
REGEX_RULES: list[dict] = [
    {"id":"AWS_ACCESS_KEY","name":"AWS Access Key","pattern":re.compile(r"AKIA[0-9A-Z]{16}", _F),"vuln_type":"hardcoded_secret","note":"AWS access key ID detected in source code.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"GITHUB_TOKEN","name":"GitHub Token","pattern":re.compile(r"ghp_[A-Za-z0-9]{36}", _F),"vuln_type":"hardcoded_secret","note":"GitHub personal access token detected in source code.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"GENERIC_API_KEY_PASSWORD","name":"Generic API Key/Password","pattern":re.compile(r'(?:api[_-]?key|api[_-]?token|secret[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|pwd)\s*[:=]\s*["\'][A-Za-z0-9@#$%^&+=!_.\-/]{8,}["\']', _F),"vuln_type":"hardcoded_secret","note":"Possible hardcoded credential or API key.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    # G-036b: the sites that actually *enforce* a secret were never reported.
    # The assignment rules above catch `KEY = "..."`, but the seven checks that
    # return 401 - `if token != "sk-mock-key"`, `if api_key != "foobar"`,
    # `if api_key != "bar"` - are comparisons, not assignments, so the whole
    # authorization gate of every mock endpoint was invisible. Comparing a
    # credential-named operand to a committed literal is CWE-798 whether the
    # literal looks like a placeholder or not: the structure is the defect.
    {"id":"HARDCODED_CREDENTIAL_COMPARISON","name":"Hardcoded credential authorization comparison","pattern":re.compile(r"\b(?:if|elif|while)\s+(?:not\s+)?[\w.\[\]]*\b(?:api[_-]?key|apikey|access[_-]?key|password|passwd|pwd|passphrase|secret|token|credential)[\w]*\s*(?:==|!=|not\s+in)\s*[\"'](?P<credval>[^\"'\s]{1,128})[\"']", _F),"vuln_type":"hardcoded_secret","note":"A credential-named value is compared against a literal, so the secret is committed to source and doubles as the authorization check.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"PRIVATE_KEY_HEADER","name":"Private Key Header","pattern":re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", _F),"vuln_type":"hardcoded_secret","note":"Private key material in source code.","severity":"Critical","cwe":"CWE-798","owasp":"A07:2021 - Identification and Authentication Failures"},
    {"id":"MD5_USAGE","name":"MD5 Usage","pattern":re.compile(r"hashlib\.md5\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']MD5|MD5CryptoServiceProvider|crypto\.createHash\s*\(\s*[\"']md5", _F),"vuln_type":"weak_crypto","note":"MD5 is cryptographically broken.","severity":"High","cwe":"CWE-327","owasp":"A02:2021 - Cryptographic Failures"},
    {"id":"SHA1_USAGE","name":"SHA-1 Usage","pattern":re.compile(r"hashlib\.sha1\s*\(|MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1|SHA1CryptoServiceProvider|crypto\.createHash\s*\(\s*[\"']sha1", _F),"vuln_type":"weak_crypto","note":"SHA-1 is deprecated for cryptographic use.","severity":"High","cwe":"CWE-327","owasp":"A02:2021 - Cryptographic Failures"},
    {"id":"FLASK_DEBUG","name":"Flask Debug Mode","pattern":re.compile(r"app\.run\s*\([^)]*debug\s*=\s*True", _F),"vuln_type":"debug_exposure","note":"Flask debug=True exposes interactive debugger in production.","severity":"High","cwe":"CWE-215","owasp":"A05:2021 - Security Misconfiguration"},
    {"id":"SUBPROCESS_SHELL_TRUE","name":"subprocess shell=True","pattern":re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True", _F),"vuln_type":"command_injection","note":"subprocess with shell=True enables shell injection.","severity":"Critical","cwe":"CWE-78","owasp":"A03:2021 - Injection"},
    {"id":"OS_SYSTEM","name":"os.system Call","pattern":re.compile(r"os\.system\s*\(", _F),"vuln_type":"command_injection","note":"os.system executes shell commands.","severity":"Critical","cwe":"CWE-78","owasp":"A03:2021 - Injection"},
    {"id":"EVAL_CALL","name":"eval() Call","pattern":re.compile(r"\beval\s*\(", _F),"vuln_type":"code_injection","note":"eval() executes arbitrary code.","severity":"Critical","cwe":"CWE-94","owasp":"A03:2021 - Injection"},
    {"id":"PYTHON_EXEC_CALL","name":"Python exec() Call","pattern":re.compile(r"(?<![.\w])exec\s*\(", _F),"vuln_type":"code_injection","note":"Python exec() executes arbitrary code.","severity":"Critical","cwe":"CWE-94","owasp":"A03:2021 - Injection","languages":{"python"}},
    {"id":"PYTHON_PICKLE_LOADS","name":"Python pickle.loads Insecure Deserialization","pattern":re.compile(r"pickle\.loads\s*\(", _F),"vuln_type":"insecure_deserialization","note":"pickle.loads deserializes untrusted data.","severity":"Critical","cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","languages":{"python"}},
    {"id":"PYTHON_PICKLE_LOAD","name":"Python pickle.load Insecure Deserialization","pattern":re.compile(r"pickle\.load\s*\(", _F),"vuln_type":"insecure_deserialization","note":"pickle.load deserializes untrusted data from a file.","severity":"Critical","cwe":"CWE-502","owasp":"A08:2021 - Software and Data Integrity Failures","languages":{"python"}},
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
    return (
        path.name.lower() in excluded_files
        or any(str(part).lower() in excluded_dirs for part in path.parts)
    )


def _should_scan(path: Path) -> bool:
    name = path.name
    return (
        (path.suffix.lower() in {str(ext).lower() for ext in SCANNABLE_EXT}
         or name in SCANNABLE_EXT)
        and not _skip(path)
    )


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


def _is_placeholder_credential(match: "re.Match[str]") -> bool:
    """True when the compared literal is a sentinel, not secret material."""
    try:
        value = (match.group("credval") or "").strip().lower()
    except (IndexError, re.error):
        return False
    if value in _CREDENTIAL_PLACEHOLDER_VALUES:
        return True
    return bool(re.fullmatch(r"<[^>]+>|\{[^}]*\}|%[sdf]", value))


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


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)
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
            if rule.get("id") == "HARDCODED_CREDENTIAL_COMPARISON" and _is_placeholder_credential(match):
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

            if rule.get("id") == "TENANT_ISOLATION_MISSING":
                if not _is_tenant_isolation_candidate(source, match, language, filepath):
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

            lineno, snippet = _snippet_for_match(rule, source, lines, match.start(), match.end())
            if _is_comment(snippet, language):
                continue
            findings.append(_make_finding(rule, filepath, lineno, snippet, language))

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
    grouped = group_findings(all_findings)
    return grouped


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    data = scan_directory(target)
    print(json.dumps({"findings": data, "enterprise_control_summary": summarize_enterprise_controls(data)}, indent=2))


