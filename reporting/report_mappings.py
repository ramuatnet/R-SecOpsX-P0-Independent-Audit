
"""
reporting/report_mappings.py

Enterprise report-facing mapping catalog for R-SecOpsX.
Pure static/reporting helper: no target code execution.
"""
from __future__ import annotations
import re

INVALID_TEXT_VALUES = {"", "none", "null", "n/a", "na", "not applicable", "unknown"}

def _norm(value: object) -> str:
    return str(value or "").strip().upper().replace("-", "_").replace(" ", "_")

def normalize_report_insights(insights, severity_distribution=None):
    """Normalize stale executive insight counts at the report-rendering boundary.

    This function only changes presentation text. It does not alter findings,
    severity scoring, detection, attack paths, SCA data, or release governance.
    """
    dist = severity_distribution or {}
    critical = int(dist.get("Critical", 0) or 0)
    high = int(dist.get("High", 0) or 0)
    critical_high = critical + high
    out = []
    for raw in insights or []:
        s = clean_mojibake(str(raw or ""))
        if s.upper().startswith("HIGH SEVERITY:"):
            s = re.sub(r"(?i)^HIGH SEVERITY:\s*\d+\s+high-severity findings?\s+present",
                       f"HIGH SEVERITY: {high} high-severity findings present", s)
        elif s.upper().startswith("HIGH RISK:"):
            # The producer (core/analyzer.py generate_insights) counts the
            # SAST-only population, but metadata.severity_distribution and the
            # severity table printed next to the insight both cover SAST plus
            # unique vulnerable dependency packages. The two therefore disagreed
            # on every scan - Juice Shop reported "HIGH RISK: 2" directly under a
            # table reading High 4. This branch previously keyed on the literal
            # prefix "HIGH SEVERITY:", which the producer has not emitted, so the
            # mismatch survived into the PDF and Excel as well.
            s = re.sub(r"(?i)^HIGH RISK:\s*\d+\s+high-severity (?:findings?|issues?)\s+present",
                       f"HIGH RISK: {high} high-severity findings present", s)
        elif s.upper().startswith("COMPLIANCE RISK:"):
            s = re.sub(r"(?i)(COMPLIANCE RISK:\s*)\d+(\s+Critical/High findings?)",
                       rf"\g<1>{critical_high}\g<2>", s)
        elif s.upper().startswith("CRITICAL:"):
            s = re.sub(r"(?i)(CRITICAL:\s*)\d+(\s+critical (?:findings|vulnerabilities)\s+identified)",
                       rf"\g<1>{critical}\g<2>", s)
        out.append(s)
    return out

def rule_key(finding: dict) -> str:
    rid = _norm(finding.get("rule_id"))
    title = _norm(finding.get("title"))
    vt = _norm(finding.get("vuln_type"))
    text = " ".join([rid, title, vt])
    # Canonical direct mappings must win over broad alias matches.
    direct = {
        "PATH_TRAVERSAL": "PATH_TRAVERSAL",
        "ZIP_SLIP": "GENERIC_ZIPSLIP",
        "LOG_INJECTION": "GENERIC_LOG_INJECTION",
        "XXE": "GENERIC_XXE",
        "SSRF": "GENERIC_SSRF",
        "XSS": "GENERIC_XSS",
    }
    for value in (rid, vt):
        if value in direct:
            return direct[value]
    aliases = [
        ("DOTNET_BINARYFORMATTER", ["BINARYFORMATTER"]),
        ("JSONNET_TYPENAMEHANDLING", ["TYPENAMEHANDLING", "JSON.NET_TYPENAME"]),
        ("DOTNET_DATACONTRACTSERIALIZER", ["DATACONTRACTSERIALIZER"]),
        ("DOTNET_XXE", ["XML_DTD", "XXE"]),
        ("DOTNET_ZIPSLIP", ["ZIPSLIP", "ZIP_SLIP"]),
        ("DOTNET_HTTPCLIENT_CERT_BYPASS", ["HTTPCLIENT", "CERTIFICATE", "BYPASS"]),
        ("DOTNET_LOG_INJECTION", ["LOG_INJECTION", "ILOGGER"]),
        ("ASP_NET_MASS_ASSIGNMENT", ["ASP.NET_MASS_ASSIGNMENT", "OVERPOSTING"]),
        ("JAVA_OBJECTINPUTSTREAM", ["OBJECTINPUTSTREAM"]),
        ("JAVA_JACKSON_DEFAULT_TYPING", ["JACKSON", "DEFAULT_TYPING"]),
        ("JAVA_SNAKEYAML_LOAD", ["SNAKEYAML", "YAML.LOAD"]),
        ("JAVA_XSTREAM_DESERIALIZATION", ["XSTREAM"]),
        ("JAVA_JNDI_LOOKUP", ["JNDI", "LOG4SHELL"]),
        ("JAVA_TRUSTMANAGER_BYPASS", ["TRUSTMANAGER", "HOSTNAMEVERIFIER"]),
        ("JAVA_REFLECTION_ACCESS", ["SETACCESSIBLE", "REFLECTION"]),
        ("SPRING_ACTUATOR_EXPOSE_ALL", ["ACTUATOR", "EXPOSE_ALL", "ALL_ENDPOINTS"]),
        ("SPRING_SECURITY_CSRF_DISABLED", ["CSRF", "PERMITALL"]),
        ("SPRING_SPEL_INJECTION", ["SPEL"]),
        ("SPRING_QUERY_INJECTION", ["@QUERY", "SPRING_DATA", "JPQL", "HQL"]),
        ("SPRING_TEMPLATE_INJECTION", ["THYMELEAF", "FREEMARKER", "VELOCITY", "TEMPLATE"]),
        ("SPRING_ASYNC_CONTEXT_LOSS", ["@ASYNC", "SECURITY_CONTEXT"]),
        ("SPRING_WEBFLUX_AUTH_GAP", ["WEBFLUX"]),
        ("SPRING_MISSING_VALIDATION", ["@VALID", "@VALIDATED", "MISSING_VALID"]),
        ("GO_COMMAND_INJECTION", ["GO_EXEC.COMMAND", "EXEC.COMMAND", "SH_-C"]),
        ("GO_TLS_INSECURE_SKIP_VERIFY", ["INSECURESKIPVERIFY"]),
        ("GO_PATH_TRAVERSAL", ["FILEPATH.JOIN", "TRAVERSAL"]),
        ("GO_SQL_INJECTION", ["FMT.SPRINTF", "SQL"]),
        ("GO_RACE_SHARED_MAP", ["SHARED_MAP", "RACE"]),
        ("GO_UNBOUNDED_READALL", ["READALL", "RESOURCE_EXHAUSTION"]),
        ("GO_GOB_DESERIALIZATION", ["GOB"]),
        ("GO_JSON_INTERFACE_UNMARSHAL", ["JSON.UNMARSHAL", "INTERFACE{}", "ANY"]),
        ("PHP_COMMAND_INJECTION", ["PHP_COMMAND", "SHELL_EXEC", "PASSTHRU", "SYSTEM("]),
        ("PHP_UNSERIALIZE", ["UNSERIALIZE"]),
        ("PHP_PHAR_DESERIALIZATION", ["PHAR"]),
        ("PHP_CURL_SSL_VERIFY_DISABLED", ["CURLOPT_SSL", "VERIFYHOST", "VERIFYPEER"]),
        ("NODE_COMMAND_INJECTION", ["CHILD_PROCESS", "EXEC", "EXECSYNC"]),
        ("NODE_EVAL_DYNAMIC_CODE", ["NEW_FUNCTION", "EVAL", "VM.RUNIN", "VM."]),
        ("NODE_SERIALIZE_UNSERIALIZE", ["NODE_SERIALIZE", "UNSERIALIZE"]),
        ("NODE_JS_YAML_LOAD", ["JS_YAML", "YAML.LOAD"]),
        ("NODE_PROTOTYPE_POLLUTION", ["PROTOTYPE_POLLUTION", "LODASH.MERGE", "DEEPMERGE"]),
        ("NODE_REDOS", ["REDOS", "REGEXP"]),
        ("NPM_SUPPLY_CHAIN", ["NPM", "LIFECYCLE", "UNPINNED"]),
        ("KAFKA_UNSAFE_DESERIALIZATION", ["KAFKA", "RABBITMQ", "MESSAGE_DESERIALIZATION"]),
        ("GRAPHQL_INTROSPECTION", ["GRAPHQL", "INTROSPECTION"]),
        ("GRAPHQL_BOLA_IDOR", ["GRAPHQL", "BOLA", "IDOR", "RESOLVER"]),
        ("GRAPHQL_COMPLEXITY_ABUSE", ["GRAPHQL", "DEPTH", "COMPLEXITY"]),
        # Keep API-abuse rules distinct so remediation is endpoint-specific.
        ("API_LOGIN_BRUTE_FORCE", ["API_LOGIN_BRUTE_FORCE", "LOGIN_BRUTE_FORCE"]),
        ("API_OTP_BRUTE_FORCE", ["API_OTP_BRUTE_FORCE", "OTP_BRUTE_FORCE"]),
        ("API_PASSWORD_RESET_ABUSE", ["API_PASSWORD_RESET_ABUSE", "PASSWORD_RESET_ABUSE"]),
        ("API_INVITE_ABUSE", ["API_INVITE_ABUSE", "INVITE_ABUSE"]),
        ("API_COUPON_REPLAY", ["API_COUPON_REPLAY", "COUPON_REPLAY"]),
        ("API_TOKEN_REFRESH_ABUSE", ["API_TOKEN_REFRESH_ABUSE", "TOKEN_REFRESH_ABUSE"]),
        ("API_PAYMENT_DUPLICATE_ACTION", ["API_PAYMENT_DUPLICATE_ACTION", "PAYMENT_DUPLICATE_ACTION"]),
        ("API_RATE_LIMIT_ABUSE", ["API_RATE_LIMIT_ABUSE", "RATE_LIMIT_ABUSE"]),
        ("TOCTOU_RACE", ["TOCTOU", "CHECK_THEN_ACT"]),
        ("TENANT_ISOLATION_FAILURE", ["TENANT", "ISOLATION"]),
        ("WORKFLOW_BYPASS", ["WORKFLOW", "APPROVAL"]),
        ("PRIVILEGE_ESCALATION", ["PRIVILEGE", "ROLE", "ADMIN"]),
        ("GENERIC_ZIPSLIP", ["ZIPSLIP", "ZIP_SLIP", "EXTRACTTODIRECTORY"]),
        ("GENERIC_LOG_INJECTION", ["LOG_INJECTION", "LOGGER"]),
        ("GENERIC_XXE", ["XXE", "DTD"]),
        ("GENERIC_SSRF", ["SSRF", "OUTBOUND_REQUEST"]),
        ("GENERIC_OPEN_REDIRECT", ["OPEN_REDIRECT", "REDIRECT"]),
        ("GENERIC_XSS", ["XSS", "RAW_ECHO", "INNERHTML"]),
    ]
    for key, needles in aliases:
        if all(n in text for n in needles if n.startswith("GRAPHQL")) and key.startswith("GRAPHQL"):
            if any(n in text for n in needles[1:]):
                return key
        elif any(n in text for n in needles):
            return key
    return rid or title or vt or "UNKNOWN_RULE"

BUSINESS_IMPACT_BY_RULE = {
    "GO_TLS_INSECURE_SKIP_VERIFY": "TLS certificate validation is disabled, allowing man-in-the-middle interception, credential theft, API response tampering, certificate spoofing, and audit/compliance failure.",
    "SPRING_ACTUATOR_EXPOSE_ALL": "Sensitive operational endpoints may expose environment variables, configuration, beans, heap dumps, mappings, and runtime diagnostics that can accelerate compromise.",
    "SPRING_SECURITY_CSRF_DISABLED": "Global CSRF disablement and broad permitAll rules can allow unauthorized state-changing requests, session abuse, and broken access-control outcomes.",
    "SPRING_SPEL_INJECTION": "User-controlled SpEL evaluation can lead to arbitrary method invocation, data disclosure, server-side code execution, and application takeover.",
    "SPRING_ASYNC_CONTEXT_LOSS": "Security context loss across async execution can execute privileged operations without the original authentication or authorization boundary.",
    "SPRING_MISSING_VALIDATION": "Missing validation permits malformed or excessive input to reach business logic, increasing injection, mass assignment, and data integrity risk.",
    "DOTNET_BINARYFORMATTER": "BinaryFormatter can instantiate attacker-controlled object graphs, enabling remote code execution, authentication bypass, or server compromise.",
    "JSONNET_TYPENAMEHANDLING": "Unsafe TypeNameHandling can deserialize attacker-controlled types and gadget chains, enabling remote code execution or sensitive data exposure.",
    "DOTNET_DATACONTRACTSERIALIZER": "Unsafe deserialization of untrusted payloads can instantiate unexpected types and compromise application state or execution flow.",
    "JAVA_OBJECTINPUTSTREAM": "ObjectInputStream on untrusted data can trigger gadget-chain execution and full JVM compromise.",
    "JAVA_JACKSON_DEFAULT_TYPING": "Jackson polymorphic/default typing can instantiate attacker-controlled classes, enabling gadget-chain exploitation.",
    "JAVA_SNAKEYAML_LOAD": "Unsafe YAML loading can construct arbitrary Java objects and trigger gadget-chain execution.",
    "JAVA_XSTREAM_DESERIALIZATION": "XStream deserialization of untrusted XML can instantiate dangerous classes and enable remote code execution.",
    "JAVA_JNDI_LOOKUP": "JNDI lookup patterns may allow attacker-controlled LDAP/RMI resolution, remote class loading, credential leakage, or Log4Shell-style compromise.",
    "JAVA_TRUSTMANAGER_BYPASS": "Custom trust managers or hostname verifiers can disable TLS identity checks and expose users and services to MITM attacks.",
    "KAFKA_UNSAFE_DESERIALIZATION": "Message consumers deserializing untrusted broker payloads can convert a poisoned message into remote code execution or persistent compromise.",
    "PHP_UNSERIALIZE": "PHP unserialize on untrusted input can trigger magic-method gadget chains, file write, SQL injection, or remote code execution.",
    "PHP_PHAR_DESERIALIZATION": "PHAR stream use on attacker-controlled paths can trigger metadata deserialization and gadget-chain execution.",
    "PHP_CURL_SSL_VERIFY_DISABLED": "Disabled cURL SSL verification permits MITM interception of API calls, credential theft, and response manipulation.",
    "GO_RACE_SHARED_MAP": "Concurrent shared map/slice access can corrupt state, bypass duplicate-action checks, or cause transaction integrity failures.",
    "GO_UNBOUNDED_READALL": "Unbounded body reads can exhaust memory/CPU and create denial-of-service conditions.",
    "GO_GOB_DESERIALIZATION": "gob decoding of untrusted data can corrupt application state and expose deserialization attack surface.",
    "GO_JSON_INTERFACE_UNMARSHAL": "Unmarshalling untrusted JSON into interface{} / any weakens schema enforcement and can enable type confusion or authorization bypass.",
    "NODE_EVAL_DYNAMIC_CODE": "Dynamic code execution can convert user or model-controlled data into arbitrary JavaScript execution and server compromise.",
    "NODE_SERIALIZE_UNSERIALIZE": "node-serialize unserialize can execute embedded functions and cause remote code execution.",
    "NODE_JS_YAML_LOAD": "Unsafe YAML loading may construct dangerous objects or load unexpected types from attacker-controlled documents.",
    "NODE_PROTOTYPE_POLLUTION": "Prototype pollution can alter application-wide object behavior, bypass authorization checks, or corrupt business logic.",
    "NODE_REDOS": "Catastrophic regular expressions can cause CPU exhaustion and denial of service under crafted input.",
    "NPM_SUPPLY_CHAIN": "Unsafe package metadata, lifecycle scripts, or unpinned dependencies increase build-time code execution and supply-chain compromise risk.",
    "GRAPHQL_INTROSPECTION": "Public introspection exposes schema, object names, and resolver structure that accelerate API abuse and authorization testing.",
    "GRAPHQL_BOLA_IDOR": "Resolver-level object access without ownership or tenant checks can expose or modify another user’s records.",
    "GRAPHQL_COMPLEXITY_ABUSE": "Missing query depth/complexity limits can allow expensive nested queries and denial of service.",
    "API_LOGIN_BRUTE_FORCE": "Login endpoints without server-side throttling and progressive backoff can enable credential stuffing, brute force, account takeover, and authentication-service abuse.",
    "API_OTP_BRUTE_FORCE": "OTP/MFA endpoints without throttling and attempt controls can enable code guessing, MFA bypass, and account takeover.",
    "API_PASSWORD_RESET_ABUSE": "Password-reset endpoints without throttling, token controls, and abuse monitoring can enable reset flooding, token spraying, and account-recovery abuse.",
    "API_INVITE_ABUSE": "Invite endpoints without throttling and authorization controls can enable invite spam, enumeration, and unauthorized account creation.",
    "API_COUPON_REPLAY": "Coupon or promotion redemption without one-time-use enforcement and transactional replay protection can enable repeated redemption and financial loss.",
    "API_TOKEN_REFRESH_ABUSE": "Token refresh endpoints without throttling, rotation, and reuse detection can enable token abuse and persistence of compromised sessions.",
    "API_PAYMENT_DUPLICATE_ACTION": "Payment or transfer operations without transactional idempotency can create duplicate charges, duplicate withdrawals, or inconsistent transaction state.",
    "API_RATE_LIMIT_ABUSE": "Abuse-prone APIs without appropriate throttling or replay controls can enable automated abuse, brute force, or duplicate actions.",
    "TOCTOU_RACE": "Check-then-act race windows can allow duplicate actions, authorization bypass, or inconsistent financial/workflow state.",
    "TENANT_ISOLATION_FAILURE": "Missing tenant boundary enforcement can expose cross-tenant data and create severe confidentiality and compliance impact.",
    "WORKFLOW_BYPASS": "Approval or workflow bypass can permit unauthorized business actions, fraudulent transactions, or policy violations.",
    "PRIVILEGE_ESCALATION": "Privilege escalation indicators can permit non-admin users to perform administrative actions or modify protected state.",
    "GENERIC_XXE": "Unsafe XML parsing can disclose files, access internal services, or trigger denial of service through external entity resolution.",
    "GENERIC_ZIPSLIP": "Unsafe archive extraction can overwrite arbitrary files, leading to code execution or configuration compromise.",
    "GENERIC_LOG_INJECTION": "Untrusted data in logs can forge audit entries, hide malicious activity, or poison downstream log-processing systems.",
    "GENERIC_SSRF": "User-controlled outbound requests can reach internal services, cloud metadata endpoints, or sensitive management interfaces.",
    "GENERIC_OPEN_REDIRECT": "Open redirects enable phishing, credential harvesting, and trusted-domain abuse.",
    "GENERIC_XSS": "Unescaped output can execute attacker-controlled script in the user’s browser and lead to session theft or credential capture.",
}

REMEDIATION_BY_RULE = {
    "DOTNET_BINARYFORMATTER": ["Remove BinaryFormatter; it is unsafe for untrusted data.", "Use System.Text.Json or explicit DTO mapping.", "Reject polymorphic type loading and validate payload schema.", "Add tests proving serialized input cannot instantiate arbitrary types."],
    "JSONNET_TYPENAMEHANDLING": ["Set TypeNameHandling to None for untrusted input.", "Use a strict SerializationBinder allow-list only when polymorphism is unavoidable.", "Deserialize into explicit DTOs and validate all fields.", "Block $type metadata from external requests."],
    "DOTNET_DATACONTRACTSERIALIZER": ["Do not deserialize untrusted XML/binary payloads into broad object types.", "Use explicit known types and schema validation.", "Disable dangerous type resolution and validate payload size.", "Prefer JSON DTOs for external input."],
    "JAVA_OBJECTINPUTSTREAM": ["Avoid ObjectInputStream for untrusted data.", "Use ObjectInputFilter with a strict class allow-list.", "Prefer JSON/protobuf with schema validation.", "Block gadget-capable classes and sign trusted serialized payloads."],
    "JAVA_JACKSON_DEFAULT_TYPING": ["Disable default typing/polymorphic deserialization for untrusted input.", "Use explicit DTO classes and allow-listed subtypes.", "Remove enableDefaultTyping/activateDefaultTyping unless strictly controlled.", "Upgrade Jackson and add deserialization regression tests."],
    "JAVA_SNAKEYAML_LOAD": ["Use SafeConstructor / safe loading APIs.", "Do not load attacker-controlled YAML into arbitrary Java objects.", "Validate YAML schema and enforce size/depth limits.", "Reject tags that instantiate custom types."],
    "JAVA_XSTREAM_DESERIALIZATION": ["Do not deserialize untrusted XML with XStream.", "Configure explicit type allow-lists.", "Disable unknown type permissions and dangerous converters.", "Prefer safe DTO parsing."],
    "JAVA_JNDI_LOOKUP": ["Remove user-controlled JNDI lookups.", "Disable remote JNDI class loading and restrict providers.", "Patch Log4j/JNDI-capable libraries.", "Block LDAP/RMI egress where not required."],
    "SPRING_ACTUATOR_EXPOSE_ALL": ["Restrict actuator exposure to health/info only.", "Protect actuator routes with Spring Security and network ACLs.", "Disable env, beans, heapdump, threaddump, mappings, and configprops in production.", "Use separate management port with restricted access."],
    "SPRING_SECURITY_CSRF_DISABLED": ["Do not globally disable CSRF for browser-based sessions.", "Enable CSRF for state-changing endpoints or implement stateless token controls.", "Avoid broad anyRequest().permitAll().", "Add tests for unauthenticated state-changing requests."],
    "SPRING_SPEL_INJECTION": ["Never pass user-controlled input to parseExpression().", "Replace dynamic expressions with allow-listed server-side operations.", "Use SimpleEvaluationContext where expression evaluation is unavoidable.", "Block type references, constructors, method calls, and bean references."],
    "SPRING_QUERY_INJECTION": ["Use parameter binding in @Query/HQL/JPQL.", "Do not concatenate user input into query strings.", "Prefer derived query methods or Criteria API with parameters.", "Add injection tests for repository methods."],
    "SPRING_TEMPLATE_INJECTION": ["Do not concatenate user input into template names or template expressions.", "Render user data only through escaped variables.", "Disable dangerous template features where possible.", "Allow-list template names and fragments."],
    "SPRING_ASYNC_CONTEXT_LOSS": ["Propagate SecurityContext explicitly for @Async operations.", "Use DelegatingSecurityContextAsyncTaskExecutor.", "Re-check authorization inside async tasks.", "Add tests proving async actions preserve user and tenant context."],
    "SPRING_MISSING_VALIDATION": ["Add @Valid/@Validated at controller boundaries.", "Use DTO-level constraints and reject invalid fields.", "Validate nested objects and collections.", "Add negative tests for malformed and over-posted input."],
    "ASP_NET_MASS_ASSIGNMENT": ["Bind requests to explicit DTOs, not domain or persistence entities.", "Use [BindNever] or model allow-lists for privileged fields.", "Validate and authorize role, tenantId, status, and isAdmin server-side.", "Add tests for over-posted privileged properties."],
    "PHP_UNSERIALIZE": ["Avoid unserialize() on untrusted input.", "Use json_decode() for external data.", "If unavoidable, use allowed_classes=false or a strict allow-list.", "Audit magic methods in reachable classes."],
    "PHP_PHAR_DESERIALIZATION": ["Do not use phar:// paths with attacker-controlled input.", "Disable PHAR stream handling where not required.", "Canonicalize and allow-list archive paths.", "Audit gadget chains in installed dependencies."],
    "PHP_CURL_SSL_VERIFY_DISABLED": ["Set CURLOPT_SSL_VERIFYPEER=true and CURLOPT_SSL_VERIFYHOST=2.", "Use trusted CA bundles and pin certificates only when operationally justified.", "Fail closed on certificate validation errors.", "Monitor outbound API failures after re-enabling verification."],
    "GO_RACE_SHARED_MAP": ["Protect shared maps/slices with sync.Mutex, sync.RWMutex, channels, or sync.Map.", "Run go test -race in CI.", "Make check-and-act operations atomic.", "Use database transactions or locks for duplicate-action workflows."],
    "GO_UNBOUNDED_READALL": ["Wrap request bodies with http.MaxBytesReader.", "Stream large inputs instead of reading all data into memory.", "Apply request timeouts and rate limits.", "Reject oversized payloads before expensive processing."],
    "NODE_EVAL_DYNAMIC_CODE": ["Remove eval(), vm execution, and new Function() for untrusted input.", "Use declarative allow-listed operations.", "Validate input against strict schemas.", "Isolate any unavoidable dynamic execution in a sandbox with no secrets/network."],
    "NODE_SERIALIZE_UNSERIALIZE": ["Do not use node-serialize unserialize on untrusted data.", "Use JSON.parse for data only.", "Remove function-bearing serialized payload support.", "Add tests rejecting _$$ND_FUNC$$_ style payloads."],
    "NODE_JS_YAML_LOAD": ["Use safe YAML schema APIs.", "Reject custom tags and executable types.", "Validate YAML schema, size, and depth.", "Avoid YAML for untrusted external input."],
    "NODE_PROTOTYPE_POLLUTION": ["Block __proto__, constructor, and prototype keys.", "Use safe merge libraries or structuredClone with allow-lists.", "Validate request bodies against schemas.", "Freeze sensitive defaults where appropriate."],
    "NODE_REDOS": ["Replace catastrophic regex with linear-time patterns.", "Use safe-regex checks in CI.", "Limit input length before regex evaluation.", "Apply request timeouts and rate limits."],
    "KAFKA_UNSAFE_DESERIALIZATION": ["Do not deserialize broker payloads into arbitrary objects.", "Use schema registry with Avro/Protobuf/JSON schema validation.", "Authenticate producers and validate message provenance.", "Quarantine malformed or unexpected message types."],
    "GRAPHQL_INTROSPECTION": ["Disable introspection in production unless explicitly required.", "Require authentication for schema discovery.", "Monitor introspection attempts.", "Avoid exposing internal object and resolver names."],
    "GRAPHQL_BOLA_IDOR": ["Enforce object ownership and tenant checks in every resolver.", "Do not rely on client-supplied IDs alone.", "Centralize authorization checks in resolver middleware.", "Add tests for cross-user and cross-tenant object access."],
    "GRAPHQL_COMPLEXITY_ABUSE": ["Set query depth and complexity limits.", "Apply cost-based throttling per user/tenant.", "Disable expensive nested queries or paginate them.", "Monitor slow GraphQL operations."],
    "API_LOGIN_BRUTE_FORCE": [
        "Apply server-side throttling per account and source IP; add tenant scoping where applicable.",
        "Use progressive backoff and bounded temporary blocking after repeated failures; do not rely on client-side controls.",
        "Return HTTP 429 for throttled requests and avoid revealing whether the account exists.",
        "Add automated tests for burst login attempts, distributed attempts, lockout/backoff, and recovery behavior.",
    ],
    "API_OTP_BRUTE_FORCE": [
        "Limit OTP verification attempts per account/session and source IP, with progressive backoff.",
        "Expire OTPs quickly, invalidate successful/failed challenge state, and enforce a maximum attempt count.",
        "Return HTTP 429 when throttled and monitor repeated verification failures.",
        "Add tests for guessing, replaying expired OTPs, distributed attempts, and lockout behavior.",
    ],
    "API_PASSWORD_RESET_ABUSE": [
        "Rate-limit reset requests per account and source IP without exposing account existence.",
        "Use short-lived, single-use reset tokens and invalidate them after successful password change.",
        "Add abuse monitoring for reset floods and token-spray patterns.",
        "Test repeated reset requests, token replay, expiry, and enumeration resistance.",
    ],
    "API_INVITE_ABUSE": [
        "Rate-limit invitations per authenticated account, tenant, destination, and source IP as appropriate.",
        "Require authorization for who may invite users and enforce tenant/domain restrictions server-side.",
        "Make invitation tokens short-lived and single-use; return 429 on abuse.",
        "Add tests for bulk invites, cross-tenant invites, replay, and enumeration.",
    ],
    "API_COUPON_REPLAY": [
        "Enforce one-time redemption server-side using an atomic transaction or unique redemption constraint.",
        "Bind redemption to the authorized account/order/tenant and validate eligibility on the server.",
        "Use idempotency or a unique redemption key for retried requests; do not rely on UI state.",
        "Rate-limit repeated redemption attempts and add tests for replay, concurrency, and cross-account use.",
    ],
    "API_TOKEN_REFRESH_ABUSE": [
        "Rate-limit refresh requests per session/account and source IP.",
        "Rotate refresh tokens and detect reuse; revoke the token family after suspicious reuse.",
        "Keep refresh tokens short-lived and bind them to the expected client/session context where appropriate.",
        "Add tests for replayed, rotated, expired, and concurrently reused refresh tokens.",
    ],
    "API_PAYMENT_DUPLICATE_ACTION": [
        "Require an idempotency key for each client retryable payment/transfer request.",
        "Enforce idempotency atomically in the server-side transaction so concurrent retries cannot create duplicate charges.",
        "Bind the idempotency record to the authenticated account and operation parameters; reject key reuse with different payloads.",
        "Add tests for retries, concurrent submissions, network-timeout replay, and mismatched idempotency keys.",
    ],
    "API_RATE_LIMIT_ABUSE": [
        "Apply endpoint-appropriate server-side throttling using account, IP, tenant, and operation dimensions.",
        "Use replay protection or idempotency for state-changing operations where duplicate execution matters.",
        "Return HTTP 429 with bounded retry behavior and emit abuse telemetry.",
        "Add automated burst, replay, concurrency, and authorization tests for the affected endpoint.",
    ],
    "TOCTOU_RACE": ["Make check-and-act logic atomic.", "Use transactions, locks, optimistic concurrency, or idempotency keys.", "Re-check authorization immediately before state change.", "Add concurrent request tests."],
    "TENANT_ISOLATION_FAILURE": ["Derive tenant context server-side from authenticated identity.", "Apply tenant filters in every repository/query.", "Block tenantId overrides from request bodies.", "Add cross-tenant negative tests."],
    "WORKFLOW_BYPASS": ["Enforce workflow state transitions server-side.", "Require approval checks before protected actions.", "Use immutable audit logs for approvals.", "Test direct API calls that skip UI workflow."],
    "PRIVILEGE_ESCALATION": ["Never trust role/admin fields from client input.", "Enforce role checks server-side for every privileged action.", "Use least-privilege service accounts.", "Add negative authorization tests."],
    "GENERIC_XXE": ["Disable DTD and external entity resolution.", "Enable secure processing features in XML parsers.", "Reject untrusted XML where possible.", "Add tests with external entity payloads."],
    "PATH_TRAVERSAL": [
        "Resolve the requested path against a fixed application base directory with Node.js path.resolve(baseDir, userPath).",
        "Verify path.relative(baseDir, resolvedPath) remains within the approved base directory; reject absolute paths and traversal escapes.",
        "Prefer server-generated file identifiers over client-supplied filesystem paths and enforce least-privilege filesystem access.",
        "Add regression tests for ../, encoded traversal, absolute paths, Windows-style traversal, and symlink escapes.",
    ],
    "GENERIC_ZIPSLIP": ["Canonicalize archive entry paths before extraction.", "Reject entries resolving outside the destination directory.", "Disallow absolute paths and parent traversal.", "Extract with a safe library wrapper."],
    "GENERIC_LOG_INJECTION": ["Sanitize CR/LF and control characters before logging.", "Use structured logging fields, not concatenated messages.", "Avoid logging secrets and tokens.", "Protect downstream log processors from injected fields."],
}

MITRE_BY_RULE = {
    "DOTNET_BINARYFORMATTER": "T1203",
    "JSONNET_TYPENAMEHANDLING": "T1203",
    "DOTNET_DATACONTRACTSERIALIZER": "T1203",
    "JAVA_OBJECTINPUTSTREAM": "T1203",
    "JAVA_JACKSON_DEFAULT_TYPING": "T1203",
    "JAVA_SNAKEYAML_LOAD": "T1203",
    "JAVA_XSTREAM_DESERIALIZATION": "T1203",
    "PHP_UNSERIALIZE": "T1203",
    "PHP_PHAR_DESERIALIZATION": "T1203",
    "KAFKA_UNSAFE_DESERIALIZATION": "T1203",
    "JAVA_JNDI_LOOKUP": "T1190",
    "SPRING_ACTUATOR_EXPOSE_ALL": "T1190",
    "SPRING_SPEL_INJECTION": "T1059",
    "NODE_EVAL_DYNAMIC_CODE": "T1059",
    "NODE_COMMAND_INJECTION": "T1059",
    "GO_COMMAND_INJECTION": "T1059",
    "PHP_COMMAND_INJECTION": "T1059",
    "GO_TLS_INSECURE_SKIP_VERIFY": "T1557",
    "JAVA_TRUSTMANAGER_BYPASS": "T1557",
    "PHP_CURL_SSL_VERIFY_DISABLED": "T1557",
    "GENERIC_OPEN_REDIRECT": "T1566",
    "GO_PATH_TRAVERSAL": "T1083",
    "GENERIC_ZIPSLIP": "T1083",
    "GENERIC_SSRF": "T1190",
    "GRAPHQL_BOLA_IDOR": "T1190",
    "TENANT_ISOLATION_FAILURE": "T1190",
    "WORKFLOW_BYPASS": "T1190",
    "PRIVILEGE_ESCALATION": "T1068",
    "NPM_SUPPLY_CHAIN": "T1195",
}

CONFIG_CRITICAL_RULES = {
    "SPRING_SECURITY_CSRF_DISABLED",
    "SPRING_ACTUATOR_EXPOSE_ALL",
    "GO_TLS_INSECURE_SKIP_VERIFY",
    "JAVA_TRUSTMANAGER_BYPASS",
    "PHP_CURL_SSL_VERIFY_DISABLED",
}

def valid_text(value: object) -> bool:
    return str(value or "").strip().lower() not in INVALID_TEXT_VALUES

def needs_business_impact_replacement(value: object) -> bool:
    text = str(value or "").strip().lower()
    return (not text or text in INVALID_TEXT_VALUES or text.startswith("enterprise static control matched"))

def needs_remediation_replacement(value: object) -> bool:
    if not value:
        return True
    if isinstance(value, str):
        vals = [value]
    else:
        vals = [str(v) for v in value]
    joined = " ".join(vals).lower()
    return (
        not joined.strip()
        or "follow secure coding best practices" in joined
        or "never deserialize data from untrusted sources with pickle" in joined
        or "use yaml.safe_load" in joined and "binaryformatter" in joined
    )

def mapping_for_rule(mapping: dict, finding: dict, default=None):
    return mapping.get(rule_key(finding), default)


# ---- final language-specific business impact additions ----
BUSINESS_IMPACT_BY_RULE.update({
    "DOTNET_BINARYFORMATTER": "Unsafe .NET BinaryFormatter deserialization can instantiate attacker-controlled types and lead to remote code execution or privilege escalation.",
    "JSONNET_TYPENAMEHANDLING": "Json.NET TypeNameHandling on untrusted data can load attacker-selected types and trigger gadget-chain execution.",
    "DOTNET_DATACONTRACTSERIALIZER": "Unsafe DataContractSerializer/NetDataContractSerializer use can deserialize attacker-controlled object graphs and compromise application integrity.",
    "JAVA_OBJECTINPUTSTREAM": "Java ObjectInputStream over untrusted data can trigger gadget chains, remote code execution, or message-consumer takeover.",
    "JAVA_JACKSON_DEFAULT_TYPING": "Jackson default typing/polymorphic deserialization can allow attacker-selected classes and gadget-chain exploitation.",
    "JAVA_SNAKEYAML_LOAD": "SnakeYAML unsafe load may instantiate arbitrary Java types from attacker-controlled YAML.",
    "JAVA_XSTREAM_DESERIALIZATION": "XStream deserialization of untrusted XML can instantiate dangerous object graphs and enable RCE.",
    "JAVA_JNDI_LOOKUP": "JNDI lookups influenced by attacker input can cause remote class loading, credential exposure, or Log4Shell-style compromise.",
    "PHP_UNSERIALIZE": "PHP unserialize on untrusted data can trigger magic-method gadget chains and application takeover.",
    "PHP_PHAR_DESERIALIZATION": "Attacker-controlled phar:// paths can trigger metadata deserialization and gadget-chain execution.",
    "NODE_EVAL_DYNAMIC_CODE": "Node dynamic code execution can run attacker-controlled JavaScript with application privileges.",
    "NODE_SERIALIZE_UNSERIALIZE": "node-serialize unsafe unserialize can execute embedded JavaScript payloads.",
    "GRAPHQL_INTROSPECTION": "Exposed GraphQL introspection can reveal schema, hidden operations, and sensitive object relationships useful for targeted attacks.",
    "GRAPHQL_BOLA_IDOR": "GraphQL resolver BOLA can allow cross-user or cross-tenant object access through attacker-controlled IDs.",
    "API_RATE_LIMIT_ABUSE": "Missing abuse controls on authentication, OTP, reset, coupon, token refresh, or payment endpoints enables brute force, replay, fraud, or account takeover.",
})
MITRE_BY_RULE.update({
    "JAVA_JNDI_LOOKUP": "T1190",
    "NODE_EVAL_DYNAMIC_CODE": "T1059",
    "GRAPHQL_BOLA_IDOR": "T1190",
    "API_RATE_LIMIT_ABUSE": "T1110",
})
# ---- end final language-specific business impact additions ----


# ---- final enterprise QA polish mappings ----
BUSINESS_IMPACT_BY_RULE.update({
    "SPRING_MVC_MASS_ASSIGNMENT_ENTITY_BINDING": "Client-controlled entity binding can over-post privileged fields such as role, isAdmin, status, balance, or tenantId, enabling privilege escalation and unauthorized data changes.",
    "SPRING_MASS_ASSIGNMENT_ENTITY_BINDING": "Client-controlled entity binding can over-post privileged fields such as role, isAdmin, status, balance, or tenantId, enabling privilege escalation and unauthorized data changes.",
    "MASS_ASSIGNMENT": "Mass assignment can let attackers set privileged fields that should only be controlled server-side, resulting in privilege escalation or business-state manipulation.",
    "ASP_NET_MASS_ASSIGNMENT": "ASP.NET model binding to domain entities can over-post privileged fields and bypass intended server-side authorization checks.",
    "TENANT_ISOLATION_FAILURE": "Missing tenant boundary enforcement can expose cross-tenant data and create severe confidentiality, contractual, and regulatory impact.",
    "GRAPHQL_BOLA_IDOR": "Resolver-level authorization gaps can expose or modify records belonging to other users or tenants through attacker-controlled object identifiers.",
    "API_RATE_LIMIT_ABUSE": "Missing rate limits, replay controls, lockout, or idempotency on abuse-prone APIs can enable brute force, OTP guessing, coupon replay, token abuse, payment duplication, and account takeover.",
    "GENERIC_XXE": "XXE can expose local files, internal network resources, credentials, and service metadata through unsafe XML parsing.",
    "GENERIC_SSRF": "SSRF can let attackers reach internal services, cloud metadata endpoints, and protected network resources from the server side.",
})

REMEDIATION_BY_RULE.update({
    "SPRING_MVC_MASS_ASSIGNMENT_ENTITY_BINDING": ["Bind requests to DTOs rather than domain entities.", "Allow-list mutable fields and block role, isAdmin, tenantId, status, balance, and permission fields.", "Validate with @Valid/@Validated and enforce authorization after binding."],
    "SPRING_MASS_ASSIGNMENT_ENTITY_BINDING": ["Bind requests to DTOs rather than domain entities.", "Allow-list mutable fields and block role, isAdmin, tenantId, status, balance, and permission fields.", "Validate with @Valid/@Validated and enforce authorization after binding."],
    "MASS_ASSIGNMENT": ["Use DTOs and explicit allow-lists for user-controlled input.", "Reject privileged fields from request bodies.", "Re-check authorization before persistence."],
    "TENANT_ISOLATION_FAILURE": ["Derive tenant context from authenticated identity, not request parameters.", "Apply mandatory tenant filters in every repository/query.", "Add cross-tenant negative tests."],
    "GRAPHQL_BOLA_IDOR": ["Authorize every resolver at object level.", "Verify owner and tenant before returning repository results.", "Add query tests for cross-user and cross-tenant IDs."],
    "API_RATE_LIMIT_ABUSE": ["Apply per-user, per-IP, and per-tenant throttles.", "Add lockout/backoff for login, OTP, reset, invite, coupon, token refresh, and payment flows.", "Use idempotency keys for state-changing actions.", "Alert on brute force, replay, and duplicate action patterns."],
})
# ---- end final enterprise QA polish mappings ----

# -----------------------------------------------------------------------------
# Final mapping corrections for client-facing report quality
# -----------------------------------------------------------------------------
FINAL_BUSINESS_IMPACT_BY_RULE = {
    "SPRING_SECURITY_CSRF_DISABLED": "Global CSRF disablement and broad permitAll rules can allow unauthorized state-changing requests, session abuse, and broken access-control outcomes.",
    "SPRING_SECURITY_BROAD_PERMITALL_EXPOSURE": "Broad permitAll exposure can make privileged routes reachable without authentication, increasing account takeover and unauthorized administration risk.",
    "MASS_ASSIGNMENT": "Mass assignment can let attackers set fields the UI never intended to expose, causing privilege escalation, tenant-boundary bypass, or business workflow abuse.",
    "GRAPHQL_INTROSPECTION_EXPOSURE": "GraphQL introspection in production can expose schema, object names, hidden mutations, and authorization-sensitive fields, accelerating API reconnaissance.",
    "GRAPHQL_RESOLVER_BOLA_IDOR": "A resolver that fetches objects by user-controlled IDs without ownership checks can expose or modify another user's or tenant's records.",
    "TENANT_ISOLATION_FAILURE": "Missing tenant-boundary enforcement can expose cross-tenant data, enable account takeover across tenants, and create severe confidentiality and compliance impact.",
    "JAVA_REFLECTION_SET_ACCESSIBLE": "Reflection access override can bypass encapsulation and security checks, enabling unauthorized access to private fields or methods and weakening sandbox assumptions.",
}

FINAL_COMPLIANCE_BY_RULE = {
    "TENANT_ISOLATION_FAILURE": {"pci_dss": "Req 7 / Req 8 - Access control and tenant data segregation", "nist": "AC-3 / AC-6 / SC-7", "nist_800_53": "AC-3 / AC-6 / SC-7", "iso27001": "A.5.15 / A.8.3 / A.8.20", "iso_27001": "A.5.15 / A.8.3 / A.8.20", "soc2": "CC6.1 / CC6.6 / CC7.2", "owasp": "A01:2021 - Broken Access Control", "cwe": "CWE-639", "mitre": "T1190"},
    "GRAPHQL_INTROSPECTION_EXPOSURE": {"pci_dss": "Req 6.2.4 - Secure API configuration", "nist": "CM-7 / AC-3 / SC-7", "nist_800_53": "CM-7 / AC-3 / SC-7", "iso27001": "A.8.9 / A.8.20", "iso_27001": "A.8.9 / A.8.20", "soc2": "CC6.6 / CC7.2", "owasp": "A05:2021 - Security Misconfiguration", "cwe": "CWE-200", "mitre": "T1595"},
    "GRAPHQL_RESOLVER_BOLA_IDOR": {"pci_dss": "Req 7 / Req 8 - Access control", "nist": "AC-3 / AC-6 / SI-10", "nist_800_53": "AC-3 / AC-6 / SI-10", "iso27001": "A.5.15 / A.8.3 / A.8.20", "iso_27001": "A.5.15 / A.8.3 / A.8.20", "soc2": "CC6.1 / CC6.6", "owasp": "A01:2021 - Broken Access Control", "cwe": "CWE-639", "mitre": "T1190"},
    "JAVA_REFLECTION_SET_ACCESSIBLE": {"pci_dss": "Req 6.2.4 - Secure coding and unsafe reflection prevention", "nist": "SI-10 / CM-7 / SA-11", "nist_800_53": "SI-10 / CM-7 / SA-11", "iso27001": "A.8.28 / A.8.29", "iso_27001": "A.8.28 / A.8.29", "soc2": "CC7.1 / CC7.2", "owasp": "A05:2021 - Security Misconfiguration", "cwe": "CWE-470", "mitre": "T1059"},
}

try:
    BUSINESS_IMPACT_BY_RULE.update(FINAL_BUSINESS_IMPACT_BY_RULE)
except Exception:
    BUSINESS_IMPACT_BY_RULE = dict(FINAL_BUSINESS_IMPACT_BY_RULE)

try:
    COMPLIANCE_BY_RULE.update(FINAL_COMPLIANCE_BY_RULE)
except Exception:
    COMPLIANCE_BY_RULE = dict(FINAL_COMPLIANCE_BY_RULE)


# V17.9.23/V17.9.24 report-quality helpers merged without removing the
# authoritative V17.9.22 mapping catalog required by core.analyzer.
# Signatures that indicate a UTF-8 -> cp1252 -> UTF-8 round trip. Used to judge
# whether decoding IMPROVED a string; a legitimate non-ASCII string such as a
# filename containing "cafe\u0301" will not have its signature count reduced, so
# the decoder leaves it alone.
_MOJIBAKE_SIGNATURES = (
    "\ufffd", "\u00c3\u0082", "\u00c3\u0083", "\u00c2\u00a2",
    "\u00e2\u0080", "\u00e2\u20ac", "\u00c3\u00a2", "\u00c2\u00ac",
    "\u00f0\u017e", "\u00e2\u0080\u0093", "\u00e2\u0080\u0099",
)


def mojibake_score(text: str) -> int:
    """How many round-trip signatures a string carries. 0 means clean."""
    if not isinstance(text, str):
        return 0
    return sum(text.count(sig) for sig in _MOJIBAKE_SIGNATURES)


def clean_mojibake(text: str) -> str:
    """Repair UTF-8 that was decoded as cp1252 and re-encoded, to any depth.

    Replaces a 9-entry lookup table that only handled single-round-trip forms,
    so it could not have fixed the triple-encoded token that actually reached the
    PDF -- and which was never called at all.

    The round trip is repeated until the string stops changing, and the result is
    accepted ONLY if its signature count strictly drops. That acceptance test is
    what makes this safe: decoding must demonstrably improve the string, so a
    legitimate non-ASCII string is returned unchanged instead of being mangled
    into something it was never meant to be.
    """
    if not isinstance(text, str) or not text:
        return text
    current = text
    for _ in range(6):                      # 6 is far beyond any real depth
        if mojibake_score(current) == 0:
            break
        try:
            candidate = current.encode("cp1252", errors="strict").decode(
                "utf-8", errors="strict")
        except (UnicodeEncodeError, UnicodeDecodeError):
            # Partially-decodable: fall back to the single-byte legacy fixups,
            # which can still remove the leading mojibake lead bytes.
            candidate = re.sub(r"[\u00c3\u0082\u00c2\u00e2\u00f0]", "", current)
            candidate = candidate.replace("\u00a2", "").replace("\u00ac", "")
        if candidate == current:
            break
        if mojibake_score(candidate) >= mojibake_score(current):
            break
        current = candidate
    return current



def clean_html_markup(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    return re.sub(r'</?[^>]+>', '', text).strip()

def normalize_fixed_versions(versions):
    if not versions:
        return ["No fixed version identified in current advisory dataset."]
    if isinstance(versions, str):
        versions = [v.strip() for v in versions.split(',') if v.strip()]
    seen, deduped = set(), []
    for value in versions:
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value); deduped.append(value)
    return deduped or ["No fixed version identified in current advisory dataset."]

def get_remediation_guidance(vuln_type: str, endpoint: str = None) -> list:
    vt, ep = str(vuln_type or '').lower(), str(endpoint or '').lower()
    if any(x in vt for x in ('supply_chain', 'lifecycle', 'npm_supply_chain')):
        return REMEDIATION_BY_RULE.get('NPM_SUPPLY_CHAIN', [])
    if 'login' in ep:
        return ['Implement per-IP and per-account rate limiting.', 'Apply progressive backoff and account-abuse controls.', 'Return HTTP 429 when limits are exceeded.', 'Add brute-force regression tests.']
    if 'payment' in ep:
        return ['Require an Idempotency-Key for state-changing payment requests.', 'Enforce idempotency inside the transaction boundary.', 'Prevent duplicate execution under retries or races.', 'Add concurrent-request regression tests.']
    if 'coupon' in ep:
        return ['Perform coupon redemption atomically.', 'Enforce a unique redemption constraint per account/coupon.', 'Reject replayed redemption attempts.', 'Add concurrent redemption regression tests.']
    return REMEDIATION_BY_RULE.get(rule_key({'vuln_type': vuln_type}), [])

# Machine-readable status identifiers belong in the payload, not in a
# client-facing sentence: an assessor reading "REVIEW_REQUIRED",
# "NOT_ATTESTABLE_BY_A_SCANNER" or "AUTH_HINT_NOT_OBSERVED" is looking at
# pipeline internals, not at a result.  This map is deliberately explicit --
# a value that is not listed is returned unchanged, so a status introduced
# later renders as itself rather than being silently rewritten or dropped.
STATUS_WORDING = {
    # governance / decision state
    'REVIEW_REQUIRED': 'Needs reviewer sign-off',
    'APPROVE_WITH_CONDITIONS': 'Approve with conditions',
    # SSDF practice verdicts
    'OBSERVED': 'Observed',
    'NOT_OBSERVED': 'Not observed',
    'NOT_ATTESTABLE_BY_A_SCANNER': 'Not attestable by a scanner',
    # licence resolution
    'RESOLVED_FROM_CANONICAL_REPORT': 'Resolved from canonical report',
    'NO_LICENSE_EVIDENCE': 'No licence evidence',
    'CANONICAL_REPORT': 'Canonical report',
    'RULE_BASED_LICENSE_POLICY_V1': 'Rule-based licence policy (v1)',
    'RULE_BASED_LICENSE_POLICY_V3': 'Rule-based licence policy (v3, qualified evidence)',
    'RULE_BASED_LICENSE_POLICY_V3_QUALIFIED_EVIDENCE': 'Rule-based licence policy (v3, qualified evidence)',
    'QUALIFIED_RESOLVED_EVIDENCE': 'Qualified resolved evidence',
    # API-BOM / ABOM field values
    'AUTH_HINT_PRESENT': 'Present',
    'AUTH_HINT_NOT_OBSERVED': 'Not observed',
    'MODEL_HINT': 'Model hint',
    'REGEX': 'Regex',
    'STATIC_EVIDENCE': 'Static evidence',
    'SOURCE_TEXT_PATTERN': 'Source text pattern',
    # vulnerability age buckets
    'LEGACY_HIGH_RISK': 'Legacy, high risk',
    'RECENT': 'Recent',
    'OLD': 'Old',
    'NOT_APPLICABLE': 'Not applicable',
    # generic null-ish values that otherwise render as shouted words
    'NOT_AVAILABLE': 'Not available',
    'UNKNOWN': 'Unknown',
    'INFERRED_FROM_DISPLAY_NAME': 'Inferred from display name',
}


def humanize_enum(value) -> str:
    """Return reader-facing wording for a known status identifier.

    Any other value -- including ordinary data such as "MIT" or a rule id --
    is returned untouched, so this can be applied at a render boundary
    without needing to know which fields are enumerated.
    """
    text = str(value if value is not None else '').strip()
    return STATUS_WORDING.get(text, text)


# Tokens meaning "no version was established". Matched explicitly because
# "UNKNOWN" is a truthy string: `if version` would happily print
# "CVSS UNKNOWN — 7.5", which reads as though a version had been named.
_CVSS_NO_VERSION = {"", "UNKNOWN", "NONE", "N/A", "NA", "NULL", "-"}


def _cvss_number(score):
    """A CVSS base score as a float, or None when the value is not one."""
    if isinstance(score, bool) or score is None:
        return None
    if isinstance(score, (int, float)):
        value = float(score)
    else:
        try:
            value = float(str(score).strip())
        except (TypeError, ValueError):
            return None
    return value if 0.0 <= value <= 10.0 else None


def format_cvss_assessment(version, score, has_vulnerability: bool = True) -> str:
    """Reader-facing CVSS cell: which version spoke, and what it said.

    All five outcomes come from real advisory data:

      --                                  nothing to score here
      CVSS 4.0 — 6.9                      version and score agree
      CVSS version unknown — 7.5          a number published with no version
      CVSS 4.0 — score unavailable        a version with no score for it
      CVSS score unavailable              neither

    The last two must not collapse into "--": "--" means no vulnerability
    exists, whereas "score unavailable" means one does and its severity is
    simply not published. Conflating them would understate a real finding.
    """
    if not has_vulnerability:
        return "--"

    if version is None:
        text = ""
    else:
        text = str(version).strip().upper().removeprefix("CVSS:").strip()
    stated = text not in _CVSS_NO_VERSION
    value = _cvss_number(score)

    if stated and value is not None:
        return f"CVSS {text} — {value:.1f}"
    if value is not None:
        return "CVSS version unknown — {0:.1f}".format(value)
    if stated:
        return f"CVSS {text} — score unavailable"
    return "CVSS score unavailable"


# ------------------------------------------------------------------ SBOM ---
# One predicate and one display order for every renderer that prints an
# advisory-derived cell (CVE, CVSS, EPSS, severity, age, reachability, fix).
# Before this existed, the PDF counted `vulnerabilities or cve or advisory_id`
# while the Excel sheet counted `cve_list / cves / additional_cves /
# vulnerability_ids / vulnerabilities[].id` -- measured on the shipped corpus
# both agreed (32 == 32), but nothing forced them to, and a divergence would
# show as prose counting a vulnerability the cells dash away (or vice versa).

_SBOM_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3,
    "info": 4, "informational": 4,
}


def pkg_has_advisory(pkg) -> bool:
    """True when the component carries at least one known vulnerability.

    Union of the predicates the PDF and Excel renderers each used alone.
    A non-dict entry is treated as having no advisory: it can render as a
    dash row but may never claim a finding.
    """
    if not isinstance(pkg, dict):
        return False
    if pkg.get("vulnerabilities") or pkg.get("cve") or pkg.get("advisory_id"):
        return True
    if pkg.get("cve_list") or pkg.get("advisory_ids"):
        return True
    for key in ("cves", "additional_cves", "vulnerability_ids"):
        val = pkg.get(key)
        if isinstance(val, list) and val:
            return True
        if isinstance(val, str) and val.strip():
            return True
    return False


def sbom_display_sort_key(pkg):
    """Reader order for the full-SBOM tables: vulnerable first, then severity.

    Components with known vulnerabilities come first ordered Critical -> High
    -> Medium -> Low (an advisory whose severity is not published sorts last
    among the vulnerable ones, never in a bucket that hides it), then every
    clean component; both groups alphabetical by name, then version. The
    payload order is manifest order, which scatters ~32 vulnerable rows
    across 823 and makes the reader hunt for them. Single source so the PDF
    table and the Excel sheet page together.
    """
    if not isinstance(pkg, dict):
        return (1, 5, "", "")
    if pkg_has_advisory(pkg):
        sev = str(pkg.get("severity")
                  or pkg.get("highest_vulnerability_severity")
                  or "").strip().casefold()
        group, rank = 0, _SBOM_SEVERITY_RANK.get(sev, 5)
    else:
        group, rank = 1, 5
    name = str(pkg.get("name") or pkg.get("component") or "").casefold()
    version = str(pkg.get("version") or pkg.get("current_version") or "").casefold()
    return (group, rank, name, version)


def license_sort_key(row):
    """Reader order for licensing tables: one contiguous block per resolved
    licence, alphabetical, components alphabetical inside it. A reviewer
    asking "what ships under LGPL here?" reads one block instead of hunting
    823 manifest-ordered rows. Tolerant of both source shapes -- the PDF's
    ``license_evidence`` rows key the component as ``package``, the Excel
    sheet reads ``sbom`` rows keyed as ``name``/``component`` -- so the two
    artifacts list the same components in the same order.
    """
    if not isinstance(row, dict):
        return ("", "", "")
    lic = str(row.get("license_resolved") or row.get("normalized_license")
              or row.get("license_declared") or row.get("license")
              or "UNKNOWN").casefold()
    name = str(row.get("package") or row.get("name")
               or row.get("component") or "").casefold()
    version = str(row.get("version") or row.get("current_version") or "").casefold()
    return (lic, name, version)


def format_attack_path_label(is_confirmed: bool) -> str:
    return ('CONFIRMED — Source-to-sink evidence validated.' if is_confirmed else
            'PATTERN-ONLY — Candidate attack path. Manual validation is required before exploitability is established.')

def get_attack_path_introduction(has_confirmed: bool, has_candidate: bool) -> str:
    if has_confirmed and has_candidate:
        return ('These represent modeled multi-step attack scenarios. Confirmed paths have validated '
                'source-to-sink evidence. Candidate paths represent conditional scenarios requiring manual validation.')
    if has_confirmed:
        return 'These represent modeled multi-step attack scenarios with validated source-to-sink evidence.'
    return 'These represent candidate attack scenarios requiring manual validation before exploitability is established.'

def format_benchmark_status(status: str) -> str:
    if status == 'DECLARED_INTENTIONAL':
        return ('Declared intentional for benchmark evaluation. This designation does not constitute '
                'a production security waiver.')
    return str(status or '')
