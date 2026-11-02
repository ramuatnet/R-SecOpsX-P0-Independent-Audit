"""UFIB category evidence contracts and the security claim interpreter.

SCHEMA: UFIB-CONTRACT-1 / UFIB-EVIDENCE-1

A detector match is an observation, not a proof. This module defines, for
every supported vulnerability category, the EXACT security claim the finding
makes, the evidence that claim requires, and the counterevidence that would
weaken or defeat it. The brain (ufib_brain.py) evaluates each finding against
its category's contract; nothing in this module knows about individual scan
rules beyond the mapping that routes a rule to its category.

DESIGN LAWS (enforced by tests, not convention):
  * Additive only. Contracts never rewrite detector output; they describe
    what the brain may conclude.
  * UNKNOWN is never satisfied. A mandatory requirement the analysis could
    not establish stays UNKNOWN and blocks confirmation.
  * No generic suppression. Counterevidence is pattern-scoped per category;
    no contract may reject a finding merely because of where it sits.
  * SCA findings are never suppressed for unreachability (mission L):
    applicability, reachability and exposure are separate dimensions.

Evidence states (mission 3.2):
  OBSERVED    directly present in the finding or its source
  INFERRED    derived from observations
  VALIDATED   checked by a validation procedure (evidex, canonical evidence)
  UNKNOWN     not established by available analysis
  CONTRADICTED inconsistent with available evidence
"""
from __future__ import annotations

import re
from typing import Any

UFIB_CONTRACT_SCHEMA = "UFIB-CONTRACT-1"
UFIB_EVIDENCE_SCHEMA = "UFIB-EVIDENCE-1"

OBSERVED = "OBSERVED"
INFERRED = "INFERRED"
VALIDATED = "VALIDATED"
UNKNOWN = "UNKNOWN"
CONTRADICTED = "CONTRADICTED"

# Finding-text scope: the collector searches the finding's own text fields.
# File scope: the collector reads the source file (bounded) -- used where the
# counterevidence lives beside the match, not inside it (middleware,
# canonicalization, pod-level security context).
SCOPE_FINDING = "finding"
SCOPE_FILE = "file"

RISKS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _ce(kind: str, pattern: str, scope: str = SCOPE_FINDING,
        decisive: bool = False, note: str = "") -> dict:
    """One counterevidence rule. `decisive` rejects; otherwise it qualifies."""
    return {"kind": kind, "pattern": re.compile(pattern, re.IGNORECASE),
            "scope": scope, "decisive": decisive, "note": note}


# ---------------------------------------------------------------------------
# Counterevidence pattern library. Every pattern is compiled once at import;
# a pattern that cannot compile fails fast here rather than mid-scan.
# ---------------------------------------------------------------------------
_SQL_PARAMETERIZED = [
    _ce("parameterized_execution",
        r"(?:execute|executemany|execute_many|query)\s*\(\s*['\"][^'\"]*['\"]\s*,",
        decisive=True,
        note="query string followed by a params argument = bound execution"),
    _ce("prepared_statement",
        # A parameterized prepare carries a placeholder IN the SQL literal
        # (? / $1 / %s / :name) or is the JDBC prepared API driven by setXxx.
        # A bare prepare() over a built string (rusqlite conn.prepare(&sql))
        # is the VULNERABLE sink itself and must never count as counterevidence
        # -- the corpus's Rust fixture proved this exact failure mode.
        r"prepareStatement\s*\(\s*['\"][^'\"]*(?:\?|%s|:\w+)|"
        r"prepareStatement\s*\([^)]*\)\s*[;.]?\s*\n?\s*set[A-Z]\w+\s*\(|"
        r"\bprepare\s*\(\s*['\"][^'\"]*(?:\?|%s|:\w+|:\w+)['\"]",
        decisive=True),
    _ce("orm_bound_query",
        # Scoped to explicit ORM/bound-parameter APIs. A bare `.get('...')`
        # also matches HashMap.get and produced a decisive false rejection on
        # the aclean/sc CustomerSearchDAOImpl row (2026-10-27) -- the map
        # accessor is not query parameterization.
        r"\bsetParameter\s*\(|createQuery\s*\(|"
        r"objects\.(?:filter|get)\s*\(|em\.(?:createQuery|find)\s*\(|"
        r"\.createNamedQuery\s*\(",
        decisive=True),
    _ce("sqlalchemy_text_binds",
        r"text\s*\(\s*['\"][^'\"]*:\w+", decisive=True,
        note="named bind parameters"),
]
_CMD_SAFE = [
    _ce("fixed_argv_list",
        r"(?:subprocess\.(?:run|call|check_output|Popen)|execve?)\s*\(\s*\[",
        decisive=True,
        note="argv list without shell= = no shell interpretation"),
    _ce("shell_false", r"shell\s*=\s*False", decisive=True),
]
_PATH_SAFE = [
    _ce("canonicalization",
        r"(?:os\.path\.)?(?:normpath|realpath|abspath|resolve)\s*\(|\.normalize\s*\(|toRealPath\s*\("),
    _ce("containment_check",
        r"(?:startswith|commonpath|relpath)\s*\(|secure_filename\s*\(|\bbasename\s*\("),
]
_SSRF_SAFE = [
    _ce("destination_allowlist",
        r"allowed_hosts|ALLOWED_HOSTS|allow_?list|is_safe_url|validate_url|"
        r"permitted_domains|urlparse\s*\([^)]*\)\.netloc"),
]
# Upload-specific: basename()/normalization is NOT containment here (it strips
# traversal, not the extension), so _PATH_SAFE must not be reused as-is.
_UPLOAD_SAFE = [
    _ce("extension_allowlist",
        r"in_array\s*\([^)]{0,80}(?:ext|type)|allowedExtensions\s*|"
        r"endsWith\s*\(\s*['\"]\.|extension_whitelist|"
        r"preg_match\s*\([^)]{0,60}(?:jpg|png|gif|pdf)"),
    _ce("generated_destination_name",
        r"random_bytes\s*\(|bin2hex\s*\(|uniqid\s*\(|uuid|tempnam\s*\(",
        note="destination name is generated, not taken from the client"),
]
_SECRET_PLACEHOLDER = [
    # NOTE: 'redacted' / [REDACTED] deliberately absent -- the report layer's
    # own privacy redaction is NOT a placeholder. Counterevidence must never
    # read a privacy control as evidence about the value's authenticity.
    _ce("placeholder_value",
        r"(?<![a-z])(?:example|sample|placeholder|dummy|fake|mock|changeme|"
        r"your[-_]??(?:api[-_]?)?key|not[-_]?a[-_]?real|insert[-_ ]??(?:your|the)"
        r"|xxxxxx)(?![a-z])",
        decisive=True,
        note="placeholder/example-shaped values are not committed secrets"),
    _ce("placeholder_shape",
        r"(?:<[^>\n]{2,}>|\{\{[^}]{0,60}\}\}|\$\{[^}\n]{0,60}\}|"
        r"\bX{6,}\b|\bx{6,}\b|\b0{6,}\b|\b\*{6,}\b|"
        r"\b(?:cp|proj|svc)[-_]??api[-_]??\w*[-_ ]??key\b)",
        decisive=True,
        note="template/placeholder-shaped values are not committed secrets"),
    _ce("synthetic_context_marker",
        r"(?:golden[- ]?corpus|synthetic|fixture|benchmark[- ]?synthetic)",
        decisive=True,
        note="synthetic corpus material is not a committed secret"),
]
_DESER_SAFE = [
    _ce("safe_loader", r"yaml\.safe_load\b|safe_load\s*\(|json\.loads\s*\(|"
                       r"RestrictedUnpickler|verify\s*=\s*", decisive=True),
]
_XSS_SAFE = [
    _ce("context_encoding",
        r"autoescape|escape\s*\(|dompurify|bleach\.(?:clean|sanitize)|"
        r"sanitize_html|textContent\s*="),
]
_RATE_LIMIT_PRESENT = [
    _ce("rate_limit_control",
        r"limiter|rate_?limit|throttle|Limiter\s*\(|slowapi|flask_limiter|"
        r"@throttled|bucket_token",
        scope=SCOPE_FILE, decisive=True,
        note="the control the rule claims is missing actually exists in this file"),
]
_VALIDATION_PRESENT = [
    _ce("input_validation",
        r"(?:validate|sanitize|clean|escape)\w*\s*\(|marshmallow|pydantic|"
        r"@\w*valid",
        scope=SCOPE_FILE,
        note="a validation/sanitization routine exists in the same file"),
]
_AUTHZ_PRESENT = [
    _ce("authorization_control",
        r"@(?:login_required|permission_required|requires_auth|authorized|"
        r"pre_authorize)|authorize\s*\(|check_permission|can\s*\(|\bis_admin\b",
        scope=SCOPE_FILE,
        note="an authorization check exists in the same file"),
]


def _k8s_pod_level_context(finding: dict, file_text: str) -> list[dict]:
    """K8S_MISSING_* counterevidence: pod-level inheritance.

    The I20 lesson: `spec.securityContext.runAsNonRoot` applies to every
    container that does not override it, and a container-scoped MISSING rule
    that ignores inheritance reports a correctly configured pod. If the
    required pattern appears anywhere in a securityContext block that sits
    BEFORE the containers list, the pod-level setting governs and the
    container-level miss is a false positive. Decisive.
    """
    rid = str(finding.get("rule_id") or "").upper()
    if not rid.startswith("K8S_MISSING_"):
        return []
    required = {
        "K8S_MISSING_RUN_AS_NON_ROOT": re.compile(r"runAsNonRoot\s*:\s*true", re.I),
        "K8S_MISSING_READ_ONLY_ROOT_FS": re.compile(r"readOnlyRootFilesystem\s*:\s*true", re.I),
        "K8S_MISSING_RESOURCE_LIMITS": re.compile(r"limits\s*:", re.I),
        "K8S_MISSING_CAPABILITIES": re.compile(r"privileged\s*:\s*false", re.I),
    }.get(rid)
    if required is None:
        return []
    lines = file_text.splitlines()
    containers_at = None
    for idx, line in enumerate(lines):
        if re.match(r"^\s*containers\s*:", line):
            containers_at = idx
            break
    pod_block = lines if containers_at is None else lines[:containers_at]
    if any(required.search(l) for l in pod_block):
        return [{
            "kind": "pod_level_inheritance",
            "state": CONTRADICTED,
            "provenance": "collector:k8s_pod_level_context",
            "detail": ("the required setting is present at pod level before "
                       "the containers list; Kubernetes inherits it into "
                       "every container that does not override it"),
        }]
    return []


# ---------------------------------------------------------------------------
# Category contracts
# ---------------------------------------------------------------------------
def _contract(category: str, claim: str, *, vuln_types: tuple,
              rule_ids: tuple = (), rule_prefixes: tuple = (),
              required: tuple, optional: tuple = (), counterevidence: list,
              requires_dataflow: bool = False,
              confirmation: str = "ALL_MANDATORY_AND_DATAFLOW",
              manual_review: bool = False,
              limitations: tuple = ()) -> dict:
    return {
        "schema": UFIB_CONTRACT_SCHEMA,
        "category": category,
        "claim": claim,
        "applies_to": {"vuln_types": vuln_types, "rule_ids": rule_ids,
                       "rule_prefixes": rule_prefixes},
        "required_evidence": required,
        "optional_evidence": optional,
        "counterevidence": counterevidence,
        "requires_dataflow": requires_dataflow,
        "confirmation_policy": confirmation,
        "manual_review": manual_review,
        "known_limitations": limitations,
    }


def _c(*names: str) -> tuple:
    return tuple(names)


CONTRACTS: dict[str, dict] = {
    "sql_injection": _contract(
        "sql_injection",
        "An externally influenced value may be incorporated into a SQL command "
        "without effective parameterization.",
        vuln_types=_c("sql_injection"),
        rule_ids=_c("TAINT_SQL_INJECTION", "JAVA_HQL_JPQL_INJECTION",
                    "JAVA_J3_SQL_INJECTION", "JAVA_JDBC_SQL_CONCAT",
                    "TAINT_SPRING_QUERY_INJECTION", "SAST-SQLI"),
        required=_c("sink", "query_construction"),
        optional=_c("data_flow", "source"),
        counterevidence=_SQL_PARAMETERIZED,
        requires_dataflow=True,
        limitations=("framework query builders may parameterize internally; "
                     "static analysis cannot prove string building reaches "
                     "the driver without interprocedural data flow"),
    ),
    "command_injection": _contract(
        "command_injection",
        "An externally influenced value may reach an operating-system command "
        "interpreter without fixed argv boundaries.",
        vuln_types=_c("command_injection", "cmdi"),
        rule_ids=_c("TAINT_CMDI", "SAST-CMDI"),
        required=_c("sink", "command_construction"),
        optional=_c("data_flow", "source"),
        counterevidence=_CMD_SAFE,
        requires_dataflow=True,
        limitations=("fixed argv lists are safe only while every element "
                     "stays constant; the brain records the argv shape it "
                     "observed, not runtime argv"),
    ),
    "code_injection": _contract(
        "code_injection",
        "An externally influenced value may be evaluated as executable code "
        "without an explicit trust boundary.",
        vuln_types=_c("code_injection"),
        rule_ids=_c("TAINT_CODE_INJECTION", "EVAL_CALL", "SAST-CODEINJ",
                    "PHP_ASSERT_REQUEST_CODE_EXEC",
                    "PHP_DYNAMIC_CALLABLE_REQUEST",
                    "PHP_CREATE_FUNCTION_REQUEST",
                    "PHP_VARIABLE_FUNCTION_REQUEST",
                    "PHP_PREG_REPLACE_EVAL_MODIFIER"),
        required=_c("sink"),
        optional=_c("data_flow", "source"),
        counterevidence=_VALIDATION_PRESENT,
        requires_dataflow=True,
        limitations=("language interpreters invoked on compile-time-constant "
                     "strings (PYTHONSTARTUP-style features) are recorded by "
                     "the evidex stage; the brain keeps their verdicts"),
    ),
    "path_traversal": _contract(
        "path_traversal",
        "An externally influenced path value may escape the intended directory "
        "containment and reach a filesystem operation.",
        vuln_types=_c("path_traversal", "zipslip"),
        rule_ids=_c("TAINT_MULTIPART_TRAVERSAL", "JAVA_J3_PATH_TRAVERSAL",
                    "JAVA_PATH_TRAVERSAL_FILE", "JAVA_J4_PATH",
                    "GENERIC_ZIPSLIP", "SAST-PATH"),
        required=_c("sink", "path_construction"),
        optional=_c("data_flow", "source"),
        counterevidence=_PATH_SAFE,
        requires_dataflow=True,
        limitations=("a `../` sequence inside a comment, example or string "
                     "literal is not a flow; the presence of normalization "
                     "helpers is counterevidence, not proof of containment"),
    ),
    "unrestricted_upload": _contract(
        "unrestricted_upload",
        "An uploaded file may be written under a client-influenced name or "
        "type without an effective extension/content-type allowlist.",
        vuln_types=_c("unrestricted_upload"),
        rule_ids=_c("PHP_UPLOAD_CLIENT_FILENAME",
                    "PHP_UPLOAD_INDIRECT_CLIENT_FILENAME",
                    "PHP_WEBSHELL_DROPPER_REQUEST"),
        rule_prefixes=_c("UPLOAD_"),
        required=_c("sink"),
        optional=_c("data_flow", "source"),
        counterevidence=_UPLOAD_SAFE,
        requires_dataflow=True,
        limitations=("basename() strips traversal but not the extension, so "
                     "it is not containment; a random generated destination "
                     "name is the only shape that removes the claim"),
    ),
    "variable_injection": _contract(
        "variable_injection",
        "Request parameters may be imported into the local symbol table, "
        "letting an attacker overwrite program variables.",
        vuln_types=_c("variable_injection"),
        rule_ids=_c("PHP_EXTRACT_REQUEST_SCOPE_INJECTION"),
        required=_c("sink"),
        optional=_c("data_flow", "source"),
        counterevidence=_VALIDATION_PRESENT,
        requires_dataflow=True,
        limitations=("extract() with EXTR_SKIP or an explicit key list is "
                     "not the same claim; only request-sourced arrays are "
                     "matched"),
    ),
    "ssrf": _contract(
        "ssrf",
        "An externally influenced URL may be fetched server-side without "
        "effective destination restriction.",
        vuln_types=_c("ssrf"),
        rule_ids=_c("TAINT_SSRF_EXPANDED", "SAST-SSRF"),
        required=_c("sink", "url_construction"),
        optional=_c("data_flow", "source"),
        counterevidence=_SSRF_SAFE,
        requires_dataflow=True,
        limitations=("an HTTP client call alone is not a flow; redirect "
                     "following after validation is only partially modeled"),
    ),
    "hardcoded_secret": _contract(
        "hardcoded_secret",
        "A literal value in a security-sensitive credential context may be an "
        "embedded secret.",
        vuln_types=_c("hardcoded_secret", "hardcoded_credential"),
        rule_ids=_c("CONFIG_CONTEXTUAL_CREDENTIAL", "GENERIC_API_KEY_PASSWORD",
                    "SAST-HARDCRED", "Hardcoded Private Key",
                    "Hardcoded Certificate"),
        rule_prefixes=_c("SECRET_"),
        required=_c("value_evidence", "credential_context"),
        optional=_c("format_validation"),
        counterevidence=_SECRET_PLACEHOLDER,
        requires_dataflow=False,
        confirmation="MANDATORY_AND_NO_CONTRADICTION",
        limitations=("static analysis cannot prove a candidate value is "
                     "active or belongs to a real system; live validation is "
                     "reported separately by the secret engine"),
    ),
    "weak_crypto": _contract(
        "weak_crypto",
        "A cryptographic operation may use an algorithm, mode or entropy "
        "source that is deprecated for security purposes.",
        vuln_types=_c("weak_crypto", "weak_random", "weak_hash",
                      "weak_encryption"),
        rule_ids=_c("JAVA_J2_WEAK_RANDOM", "SAST-WEAKCRYPTO"),
        rule_prefixes=_c("CBOM-", "CRYPTO_"),
        required=_c("api_usage"),
        optional=_c("data_flow"),
        counterevidence=[],
        requires_dataflow=False,
        confirmation="MANDATORY_AND_NO_CONTRADICTION",
        limitations=("context decides severity (captcha/etag identifiers vs "
                     "token generation); the brain records usage context, "
                     "not proven security degradation"),
    ),
    "insecure_deserialization": _contract(
        "insecure_deserialization",
        "Untrusted input may be deserialized into executable objects without "
        "type restriction.",
        vuln_types=_c("insecure_deserialization", "deserialization"),
        rule_ids=_c("SAST-DESER", "JAVA_DESER"),
        required=_c("sink"),
        optional=_c("data_flow", "source"),
        counterevidence=_DESER_SAFE,
        requires_dataflow=True,
        limitations=("gadget-chain exploitability is not established by the "
                     "deserialization call alone"),
    ),
    "xss": _contract(
        "xss",
        "Externally influenced data may be rendered into a browser context "
        "without context-appropriate encoding.",
        vuln_types=_c("xss"),
        rule_ids=_c("SAST-XSS"),
        required=_c("sink"),
        optional=_c("data_flow", "source"),
        counterevidence=_XSS_SAFE,
        requires_dataflow=True,
        limitations=("framework auto-escaping (React JSX text, Jinja2) is "
                     "implicit and not always visible at the sink line"),
    ),
    "control_gap": _contract(
        "control_gap",
        "A security control (rate limiting, authorization or validation) may "
        "be absent at an endpoint that processes untrusted requests.",
        vuln_types=_c("rate_limit", "brute_force", "api_abuse", "idor",
                      "bola", "missing_authorization", "mass_assignment"),
        rule_ids=_c("MISSING_RATE_LIMIT_ENDPOINT", "API_LOGIN_BRUTE_FORCE",
                    "API_ABUSE", "SAST-IDOR", "MISSING_AUTHZ"),
        required=_c("endpoint_context"),
        optional=_c(),
        counterevidence=_RATE_LIMIT_PRESENT + _AUTHZ_PRESENT,
        requires_dataflow=False,
        confirmation="MANUAL_REVIEW_ONLY",
        manual_review=True,
        limitations=("absence of a control in the analyzed file does not "
                     "prove absence in the execution path: middleware, "
                     "decorators and gateway policies are outside static "
                     "single-file scope; these findings are qualified, never "
                     "auto-confirmed"),
    ),
    "sca_vulnerability": _contract(
        "sca_vulnerability",
        "A resolved dependency version falls within an advisory's affected "
        "range for the claimed identifier.",
        vuln_types=_c("sca", "vulnerable_dependency"),
        rule_ids=_c("SCA-VULN-DEP"),
        required=_c("advisory", "package_identity"),
        optional=_c("reachability"),
        counterevidence=[],
        requires_dataflow=False,
        confirmation="MANDATORY_AND_NO_CONTRADICTION",
        limitations=("reachability of the vulnerable function is a separate "
                     "dimension and never suppresses the advisory applicability "
                     "claim (mission L)"),
    ),
    "iac_misconfiguration": _contract(
        "iac_misconfiguration",
        "A declarative infrastructure resource states a configuration the "
        "platform's own semantics treat as insecure or non-hardened.",
        vuln_types=_c("iac", "kubernetes", "terraform", "docker"),
        rule_ids=_c(),
        # IMAGE_ (T-9.19): saved/inspected image config is the same
        # declarative posture as its Dockerfile twin -- DOCKER_SECRET_IN_ENV
        # already resolves here; without the prefix the SECRET/KEY tokens
        # routed IMAGE_* posture claims into the hardcoded_secret
        # value-evidence contract they never made (rejected observations).
        rule_prefixes=_c("TF_", "K8S_", "DOCKER_", "IAC-", "IMAGE_"),
        required=_c("config_declaration"),
        optional=_c(),
        counterevidence=[_ce("pod_level_inheritance",
                             r"runAsNonRoot\s*:\s*true|readOnlyRootFilesystem\s*:\s*true",
                             scope=SCOPE_FILE, decisive=False,
                             note="qualified; exact decisive check in the brain")],
        requires_dataflow=False,
        confirmation="MANDATORY_AND_NO_CONTRADICTION",
        limitations=("the declared configuration is the evidence; effective "
                     "runtime state may differ through overrides the file "
                     "does not show"),
    ),
    "xxe": _contract(
        "xxe",
        "An XML parser may resolve external entities because DTD/external "
        "entity processing is not visibly disabled.",
        vuln_types=_c("xxe"),
        rule_ids=_c("JAVA_XXE_PARSER"),
        required=_c("sink"),
        optional=_c(),
        counterevidence=_VALIDATION_PRESENT,
        requires_dataflow=False,
        confirmation="MANDATORY_AND_NO_CONTRADICTION",
        limitations=("parser factory defaults may be secured outside the "
                     "matched file"),
    ),
    "reflection": _contract(
        "reflection",
        "Reflection may bypass declared access controls when "
        "setAccessible-style escalation reaches a security-relevant member.",
        vuln_types=_c("reflection"),
        rule_ids=_c("JAVA_REFLECTION_SETACCESSIBLE"),
        required=_c("sink"),
        optional=_c("data_flow"),
        counterevidence=_VALIDATION_PRESENT,
        requires_dataflow=True,
        limitations=("framework code requires setAccessible for legitimate "
                     "introspection; context decides, and the brain records "
                     "it rather than rejecting"),
    ),
    "jndi": _contract(
        "jndi",
        "An externally influenced value may reach a JNDI lookup and trigger "
        "remote class loading.",
        vuln_types=_c("jndi"),
        rule_ids=_c("JAVA_JNDI_LOG4SHELL_LOOKUP"),
        required=_c("sink"),
        optional=_c("data_flow"),
        counterevidence=[],
        requires_dataflow=True,
        limitations=("patch-level protection (log4j2.formatMsgNoLookups) is "
                     "configuration outside the matched line"),
    ),
    "ldap_injection": _contract(
        "ldap_injection",
        "An externally influenced value may be incorporated into an LDAP "
        "filter without escaping.",
        vuln_types=_c("ldap_injection"),
        rule_ids=_c("JAVA_J4_LDAP"),
        required=_c("sink"),
        optional=_c("data_flow"),
        counterevidence=[],
        requires_dataflow=True,
        limitations=("LDAP escaping helpers outside the matched file are not "
                     "modeled"),
    ),
    "llm_security": _contract(
        "llm_security",
        "An LLM-relevant pattern (prompt handling, output use, secret "
        "exposure) may create the claimed risk in an AI-enabled flow.",
        vuln_types=_c("llm", "prompt_injection"),
        rule_ids=_c(),
        rule_prefixes=_c("LLM0", "PROMPT_", "AI_"),
        required=_c("pattern_match"),
        optional=_c("ai_context"),
        counterevidence=[],
        requires_dataflow=False,
        confirmation="MANUAL_REVIEW_ONLY",
        manual_review=True,
        limitations=("prompt patterns are lexical; the claimed behavior "
                     "(untrusted instruction flow, output execution) needs "
                     "flow evidence the lexical layer cannot produce"),
    ),
    "pii_privacy": _contract(
        "pii_privacy",
        "A personal-data element may be present in the scanned application "
        "without a established exposure sink.",
        vuln_types=_c("privacy", "pii"),
        rule_ids=_c("PII_PATTERN_OBSERVED"),
        required=_c("value_evidence"),
        optional=_c("exposure_sink"),
        counterevidence=[],
        requires_dataflow=False,
        confirmation="MANUAL_REVIEW_ONLY",
        manual_review=True,
        limitations=("pattern matches and checksums never prove a value "
                     "belongs to a real individual (mission H); the privacy "
                     "engine's own classification travels with the finding"),
    ),
}

CONTRACTS["component_inventory"] = _contract(
    "component_inventory",
    "A declared or resolved component is reported present in the dependency "
    "inventory at the claimed version.",
    vuln_types=_c("component", "inventory"),
    rule_ids=_c("SBOM-COMPONENT-INVENTORY"),
    rule_prefixes=_c("SBOM-"),
    required=_c("package_identity"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANDATORY_AND_NO_CONTRADICTION",
    limitations=("inventory presence is not vulnerability applicability; "
                 "advisory claims are measured by the sca_vulnerability "
                 "contract with their own CVE identity"),
)

DEFAULT_CONTRACT = _contract(
    "_default",
    "The detector observed a pattern associated with a security concern; the "
    "category-specific claim could not be established.",
    vuln_types=_c(),
    required=_c("pattern_match"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANUAL_REVIEW_ONLY",
    manual_review=True,
    limitations=("no category contract matched this rule; the finding is "
                 "qualified for manual review rather than auto-confirmed -- "
                 "an unmatched category must never be confirmed silently"),
)


# ---------------------------------------------------------------------------
# Resolution + claim interpretation
# ---------------------------------------------------------------------------
def resolve_category(finding: dict) -> str:
    # Identity-driven resolution comes first: an advisory-backed dependency
    # finding may carry the advisory id (GHSA-...) as its rule string, which
    # no token rule should guess at. The (package, cve) identity IS the claim.
    if str(finding.get("cve") or "").strip() and \
            str(finding.get("package") or "").strip():
        return "sca_vulnerability"
    vuln = str(finding.get("vuln_type") or "").strip().lower()
    rid = str(finding.get("rule_id") or "").strip().upper()
    for key, c in CONTRACTS.items():
        applies = c["applies_to"]
        if vuln in {v.lower() for v in applies["vuln_types"]}:
            return key
        if rid in {r.upper() for r in applies["rule_ids"]}:
            return key
    for key, c in CONTRACTS.items():
        prefixes = tuple(p.upper() for p in c["applies_to"]["rule_prefixes"])
        if prefixes and rid.startswith(prefixes):
            return key
    # Token rules over the rule id: ordered, most specific families first
    # (AI before EXEC so tool-execution claims stay LLM), keyed to the
    # measured inventory rather than guessed.
    by_token = _resolve_by_tokens(rid)
    if by_token:
        return by_token
    # last-resort substring heuristics on the vulnerability type, kept narrow
    # and explicit so an unknown stays unknown instead of guessing a category.
    substring_map = (
        ("sql", "sql_injection"), ("injection", "code_injection"),
        ("traversal", "path_traversal"), ("zipslip", "path_traversal"),
        ("ssrf", "ssrf"), ("secret", "hardcoded_secret"),
        ("credential", "hardcoded_secret"), ("crypto", "weak_crypto"),
        ("random", "weak_crypto"), ("deserial", "insecure_deserialization"),
        ("pickle", "insecure_deserialization"), ("xss", "xss"),
        ("xxe", "xxe"), ("jndi", "jndi"), ("ldap", "ldap_injection"),
        ("rate_limit", "control_gap"), ("brute", "control_gap"),
        ("idor", "control_gap"), ("bola", "control_gap"),
        ("pii", "pii_privacy"), ("privacy", "pii_privacy"),
    )
    for token, key in substring_map:
        if token in vuln:
            return key
    return "_default"


def get_contract(category: str) -> dict:
    return CONTRACTS.get(category, DEFAULT_CONTRACT)


# ---------------------------------------------------------------------------
# Additional category contracts (Phase 5 completion, driven by the measured
# rule inventory: every engine-shipped rule must resolve to a contract that
# states its actual claim -- an unmatched category is manual-review, never
# silently confirmed).
# ---------------------------------------------------------------------------
CONTRACTS["transport_security"] = _contract(
    "transport_security",
    "A TLS/certificate validation control may be disabled or bypassed, "
    "allowing interception of protected connections.",
    vuln_types=_c("tls_bypass", "weak_tls"),
    required=_c("sink"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANDATORY_AND_NO_CONTRADICTION",
    limitations=("the disabled validation is a direct reading; whether the "
                 "connection carries sensitive traffic is context outside "
                 "the matched line"),
)
CONTRACTS["session_security"] = _contract(
    "session_security",
    "A session/cookie/JWT mechanism may be configured or handled in a way "
    "that weakens session integrity or authenticity checks.",
    vuln_types=_c("session", "cookie", "jwt", "csrf"),
    required=_c("config_declaration"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANDATORY_AND_NO_CONTRADICTION",
    limitations=("framework cookie defaults may be tightened in a central "
                 "settings module outside the matched file"),
)
CONTRACTS["business_logic"] = _contract(
    "business_logic",
    "A business-rule invariant (ownership, workflow sequencing, transaction "
    "boundaries, race safety) may not be enforced on the observed path.",
    vuln_types=_c("business_logic", "race_condition", "workflow_bypass"),
    required=_c("pattern_match"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANUAL_REVIEW_ONLY",
    manual_review=True,
    limitations=("static analysis cannot establish the complete business "
                 "invariant; qualified findings are the honest maximum "
                 "(mission J)"),
)
CONTRACTS["security_misconfiguration"] = _contract(
    "security_misconfiguration",
    "A security-sensitive configuration may be set permissively (debug "
    "enabled, wildcard CORS, exposed management endpoint).",
    vuln_types=_c("security_misconfiguration", "cors", "debug_mode"),
    required=_c("config_declaration"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANDATORY_AND_NO_CONTRADICTION",
    limitations=("a configuration key in a file is not proof of an effective "
                 "runtime setting; environment overrides are outside scope"),
)
CONTRACTS["redos"] = _contract(
    "redos",
    "A regular expression with catastrophic backtracking potential may be "
    "evaluated against externally influenced input.",
    vuln_types=_c("redos"),
    required=_c("pattern_match"),
    optional=_c(),
    counterevidence=[],
    requires_dataflow=False,
    confirmation="MANDATORY_AND_NO_CONTRADICTION",
    limitations=("exploitability depends on regex engine backtracking "
                 "behavior that static analysis cannot execute"),
)
CONTRACTS["prototype_pollution"] = _contract(
    "prototype_pollution",
    "Externally influenced keys may reach an object-merge path that mutates "
    "constructor prototypes.",
    vuln_types=_c("prototype_pollution"),
    required=_c("sink"),
    optional=_c("data_flow"),
    counterevidence=[],
    requires_dataflow=True,
    confirmation="ALL_MANDATORY_AND_DATAFLOW",
    limitations=("merge-library hardening against __proto__ keys is not "
                 "always visible at the sink"),
)
CONTRACTS["log_injection"] = _contract(
    "log_injection",
    "Externally influenced content may reach a log sink without "
    "normalization, enabling forged or injected log entries.",
    vuln_types=_c("log_injection", "crlf_injection", "header_injection"),
    required=_c("sink"),
    optional=_c("data_flow"),
    counterevidence=[],
    requires_dataflow=True,
    limitations=("structured-logging frameworks may neutralize control "
                 "characters at the sink boundary"),
)
CONTRACTS["open_redirect"] = _contract(
    "open_redirect",
    "An externally influenced destination may drive a redirect without an "
    "allow-list check.",
    vuln_types=_c("open_redirect"),
    required=_c("sink"),
    optional=_c("data_flow"),
    counterevidence=_SSRF_SAFE,
    requires_dataflow=True,
    limitations=("relative-destination guards are framework-provided and "
                 "not always visible at the sink line"),
)
CONTRACTS["memory_safety"] = _contract(
    "memory_safety",
    "A memory-unsafe operation (use-after-free, format-string as format, "
    "unbounded string function) may corrupt process memory.",
    vuln_types=_c("memory_safety", "use_after_free", "format_string"),
    required=_c("sink"),
    optional=_c("data_flow"),
    counterevidence=[],
    requires_dataflow=True,
    confirmation="ALL_MANDATORY_AND_DATAFLOW",
    limitations=("compiler hardening (ASLR, stack canaries) bounds impact "
                 "but does not negate the defect"),
)

# Ordered token rules over rule_id. Order matters: AI/LLM tokens must win
# over EXEC/TOOL (AUTONOMOUS_TOOL_EXECUTION is not command injection), and
# secret tokens before session (KEY in JWT_SIGNING_SECRET is a credential).
_RULE_TOKEN_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("llm_security", (
        "MODEL", "RAG_", "AGENT", "LLM", "AUTONOMOUS", "TOOL", "PROMPT",
        "TRAINING", "EMBEDDING", "VDB_", "COMP_AI", "GOV_MODEL",
        "FUNCTION_CALLING", "NO_HUMAN_REVIEW", "SOURCE_GROUNDING",
        "SYSTEM_PROMPT", "UNSIGNED_OR_UNTRUSTED", "UNTRUSTED_MODEL",
        "DATA_UNTRUSTED", "MEMORY_", "TRANSFORMERS", "TORCH_")),
    ("hardcoded_secret", (
        "API_KEY", "_KEY", "KEY_", "TOKEN", "SECRET", "CREDENTIAL",
        "PASSWORD", "PRIVATE_KEY", "CERTIFICATE", "WEBHOOK", "OAUTH")),
    ("xxe", ("XXE", "XML_ENTITIES", "DTD_PROCESSING")),
    ("sql_injection", ("SQL", "NOSQL", "FROMSQLRAW", "JOOQ", "JDBC",
                       "QUERY_ANNOTATION")),
    ("code_injection", (
        "SPEL", "TEMPLATE_INJECTION", "THYMELEAF", "FREEMARKER", "VELOCITY",
        "RENDER_STRING", "FROM_STRING", "EVAL", "CODE_INJECTION", "VM_FUNCTION",
        "UNSAFE_EVAL", "EXEC_CALL", "XPATH", "INCLUDE_CONCAT")),
    ("command_injection", (
        "COMMAND", "CHILD_PROCESS", "PROCESS_START", "EXEC", "SHELL_TRUE",
        "OS_SYSTEM", "SYSTEM_VARIABLE", "CMD_INJECTION", "SUBPROCESS")),
    ("insecure_deserialization", (
        "DESERIALIZATION", "DESER", "BINARYFORMATTER", "DATACONTRACT",
        "JACKSON", "SNAKEYAML", "UNSAFE_LOAD", "PICKLE", "UNMARSHAL",
        "XSTREAM", "UNSERIALIZE", "GOB_DECODE", "TYPENAMEHANDLING",
        "JSON_UNMARSHAL_INTERFACE")),
    ("path_traversal", (
        "TRAVERSAL", "PATH_", "_PATH", "ZIPSLIP", "EXTRACTALL", "FILEPATH",
        "LFI_RFI", "TAR_EXTRACTALL")),
    ("ssrf", ("SSRF",)),
    ("xss", ("XSS",)),
    ("open_redirect", ("OPEN_REDIRECT",)),
    ("log_injection", ("LOG_INJECTION", "HEADER_INJECTION", "HOST_HEADER")),
    ("redos", ("REDOS",)),
    ("prototype_pollution", ("PROTOTYPE_POLLUTION",)),
    ("transport_security", (
        "TLS", "SSL", "CERT_VALIDATION", "CERT_CALLBACK", "TRUSTMANAGER",
        "TRUST_BYPASS", "CURL_SSL_VERIFY")),
    ("session_security", (
        "COOKIE", "SESSION", "CSRF", "JWT")),
    ("weak_crypto", (
        "WEAK_RANDOM", "RANDOMNESS", "MD5", "SHA1", "DES", "RC4", "AES",
        "RSA", "ECC", "CIPHER", "CBC")),
    ("sca_vulnerability", ("SUPPLY_CHAIN",)),
    ("security_misconfiguration", (
        "DEBUG", "CORS", "ACTUATOR", "PERMITALL", "AUTH_GAP", "WILDCARD",
        "EXPOSE_ALL")),
    ("control_gap", (
        "IDOR", "GRAPHQL", "BOLA", "RATE_LIMIT", "BRUTE", "ABUSE",
        "MISSING_VALIDATION", "UNBOUNDED")),
    ("business_logic", (
        "CLIENT_ASSIGNED", "PRIVILEGE_ESCALATION", "MASS_ASSIGNMENT",
        "TENANT", "WORKFLOW", "RACE", "DUPLICATE_ACTION", "OVERPOSTING",
        "TX_ORIGIN", "UNCHECKED_CALL", "CACHEABLE_USER_KEY",
        "ASYNC_CONTEXT_LOSS", "CROSS_TENANT")),
    ("memory_safety", (
        "USE_AFTER_FREE", "FORMAT_STRING", "UNSAFE_STRING_FUNCTION")),
)

# Engine-shipped rules with no honest category home yet. They are held for
# manual review via the DEFAULT contract -- documented here so the invariant
# test stays honest instead of silently pretending coverage.
DOCUMENTED_DEFAULT_RULES = frozenset({
    "NODE_WEBSOCKET_SINK",       # generic sink observation; no claim yet
})


def _resolve_by_tokens(rid_upper: str) -> str | None:
    for cat, tokens in _RULE_TOKEN_RULES:
        for token in tokens:
            if token in rid_upper:
                return cat
    return None


def _has_value_evidence(finding: dict) -> bool:
    """True when the finding's own text carries a literal VALUE rather than
    only an identifier. A quoted string that IS a credential keyword (the
    form field's name, the config key's name) is an identifier, not a value
    -- mission 3.3's exact example."""
    text = " ".join(str(finding.get(k) or "") for k in
                    ("snippet", "evidence", "evidence_match"))
    keywords = {"password", "passwd", "pwd", "token", "secret", "key",
                "api_key", "apikey", "access_key", "secret_key", "auth",
                "authorization", "credential", "ssn", "email", "user",
                "username", "client_secret"}
    for m in re.finditer(r"[\"']([^\"']{4,})[\"']", text):
        candidate = m.group(1).strip().lower()
        # Only a bare credential KEYWORD (the field's name, not a value)
        # disqualifies value evidence -- a lowercase-dash "identifier shape"
        # is exactly what real API keys look like, so shape alone must never
        # downgrade a claim.
        if candidate in keywords:
            continue
        return True
    if re.search(r"\b\d{4,}\b", text):
        return True
    # Unquoted credential-shaped tokens (ghp_..., base64 runs, long hex):
    # a 16+ character alphanumeric run is a value-shaped literal even without
    # quotes -- the secrets corpus formats prove this shape.
    if re.search(r"\b[A-Za-z0-9+/=]{16,}\b", text):
        return True
    return bool(re.search(r"\bAKIA\b", text))


def build_claim(category: str, finding: dict,
                file_value_evidence: bool | None = None) -> tuple[str, str]:
    """Return (claim_text, strength). The claim never says more than the
    evidence shows: STRENGTH is the brain's honest classification of what the
    observation supports. `file_value_evidence` is the brain's file-context
    consult for value-blind findings (the secrets engine emits identifier-only
    evidence while the literal sits in the scanned file)."""
    contract = get_contract(category)
    text = " ".join(str(finding.get(k) or "") for k in
                    ("snippet", "evidence", "taint_path"))
    taint_ok = bool(
        finding.get("taint_validated")
        or (isinstance(finding.get("evidence_validation_detail"), dict)
            and finding["evidence_validation_detail"].get("taint_validated")))
    sink_ok = bool(
        finding.get("sink_validated") is True
        or (isinstance(finding.get("evidence_validation_detail"), dict)
            and finding["evidence_validation_detail"].get("sink_valid") is True))
    cve = str(finding.get("cve") or "").strip()
    iac_declared = str(finding.get("rule_id") or "").upper().startswith(
        ("TF_", "K8S_", "DOCKER_", "IAC-", "IMAGE_"))

    if category == "sca_vulnerability":
        strength = "STRONG" if cve else "WEAK"
    elif iac_declared:
        # The configuration declaration is the evidence (finding_model's
        # documented IaC stance): a direct reading, not a flow guess.
        strength = "STRONG" if text.strip() else "WEAK"
    elif taint_ok and sink_ok:
        strength = "STRONG"
    elif category == "hardcoded_secret":
        # A variable NAMED like a credential is an identifier-only match; a
        # literal VALUE in a credential context is the evidence the claim
        # needs (mission 3.3's exact example). The literal may live in the
        # scanned file rather than in the finding object.
        if _has_value_evidence(finding) or file_value_evidence:
            strength = "ADEQUATE"
        else:
            strength = "WEAK"
    elif text.strip():
        strength = "ADEQUATE"
    else:
        strength = "WEAK"
    return contract["claim"], strength


def contract_summary(category: str) -> dict:
    """Compact contract view for reports/audit: what the category demands."""
    c = get_contract(category)
    return {
        "schema": c["schema"],
        "category": c["category"],
        "claim": c["claim"],
        "required_evidence": list(c["required_evidence"]),
        "optional_evidence": list(c["optional_evidence"]),
        "requires_dataflow": c["requires_dataflow"],
        "confirmation_policy": c["confirmation_policy"],
        "manual_review": c["manual_review"],
        "known_limitations": list(c["known_limitations"]),
        "counterevidence_kinds": [ce["kind"] for ce in c["counterevidence"]],
    }
