from __future__ import annotations

import re
from pathlib import Path

from core.owasp_mappings import owasp_llm_reference as _core_owasp_llm_reference
from core.atlas_mappings import enrich_with_atlas
from core.nist_aml_mappings import enrich_with_nistaml

LLM_EXCLUDED_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".nuxt", "__pycache__", ".venv", "venv"}
LLM_SCANNABLE_EXTENSIONS = {".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts", ".go", ".php", ".rb", ".rs", ".cs", ".c", ".cpp", ".h", ".hpp", ".swift", ".m", ".mm", ".scala", ".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf"}

def _should_scan(path: Path) -> bool:
    if not path.is_file() or path.suffix.lower() not in LLM_SCANNABLE_EXTENSIONS:
        return False
    return not any(part.lower() in LLM_EXCLUDED_DIRS for part in path.parts)



LLM_RULES = [
    {
        "rule_id": "LLM01_PROMPT_INJECTION",
        "title": "LLM Prompt Injection Risk",
        "patterns": [
            r"ignore\s+previous\s+instructions",
            r"system\s*prompt",
            r"override\s+instructions",
            r"jailbreak",
            r"prompt\s*=\s*input\(",
        ],
        "severity": "High",
        "vuln_type": "llm_prompt_injection",
    },
    {
        "rule_id": "LLM02_INSECURE_OUTPUT_HANDLING",
        "title": "LLM Insecure Output Handling",
        "patterns": [
            r"eval\(",
            r"exec\(",
            r"os\.system\(",
            r"subprocess\.",
        ],
        "severity": "Critical",
        "vuln_type": "llm_insecure_output",
    },
    {
        "rule_id": "LLM03_TRAINING_DATA_POISONING",
        "title": "LLM Training Data Poisoning Risk",
        "patterns": [
            r"load_training_data",
            r"train_model",
            r"fine_tune",
            r"external_dataset",
        ],
        "severity": "High",
        "vuln_type": "llm_data_poisoning",
    },
    {
        "rule_id": "LLM04_MODEL_DENIAL_OF_SERVICE",
        "title": "LLM Model DoS Risk",
        "patterns": [
            r"max_tokens\s*=\s*999999",
            r"while\s+True",
            r"for\s+.*range\(999999",
        ],
        "severity": "High",
        "vuln_type": "llm_model_dos",
    },
    {
        "rule_id": "LLM05_SUPPLY_CHAIN_VULNERABILITY",
        "title": "LLM Supply Chain Risk",
        "patterns": [
            r"from\s+langchain",
            r"from\s+llama_index",
            r"pip\s+install",
            r"model_download",
        ],
        "severity": "High",
        "vuln_type": "llm_supply_chain",
    },
    {
        "rule_id": "LLM06_SENSITIVE_INFORMATION_DISCLOSURE",
        "title": "LLM Sensitive Information Disclosure",
        "patterns": [
            r"print\(.*api[_-]?key",
            r"print\(.*secret",
            r"print\(.*system[_-]?prompt",
            r"return.*api[_-]?key",
            r"return.*secret",
            r"return.*token",
            r"system[_-]?prompt\s*=",
            r"prompt_template.*secret",
            r"memory.*secret",
            r"vector.*secret",
            r"OPENAI_API_KEY\s*=",
            r"ANTHROPIC_API_KEY\s*=",
        ],
        "severity": "Critical",
        "vuln_type": "llm_sensitive_disclosure",
    },
    {
        "rule_id": "LLM07_INSECURE_PLUGIN_DESIGN",
        "title": "LLM Insecure Plugin Design",
        "patterns": [
            r"plugin.execute",
            r"tool.run",
            r"browser.open",
            r"shell.exec",
        ],
        "severity": "High",
        "vuln_type": "llm_insecure_plugin",
    },
    {
        "rule_id": "LLM08_EXCESSIVE_AGENCY",
        "title": "LLM Excessive Agency",
        "patterns": [
            r"auto_approve\s*=\s*True",
            r"approval_required\s*=\s*False",
            r"run_shell\s*=\s*True",
        ],
        "severity": "Critical",
        "vuln_type": "llm_excessive_agency",
    },
    {
        "rule_id": "LLM09_OVERRELIANCE",
        "title": "LLM Overreliance Risk",
        "patterns": [
            r"accept_response_without_validation",
            r"trust_model_output",
            r"auto_execute_response",
        ],
        "severity": "Medium",
        "vuln_type": "llm_overreliance",
    },

    {
    "rule_id": "LLM10_MODEL_THEFT",
    "title": "LLM Model Theft Risk",
    "patterns": [
        r"download_model",
        r"export_model_weights",
        r"model\.state_dict",
        r"torch\.save\(.*model",
        r"pickle\.dump\(.*model",
        r"save_pretrained",
        r"dump_embeddings",
        r"copy_checkpoint",
        r"checkpoint.*copy",
    ],
    "severity": "Critical",
    "vuln_type": "llm_model_theft",
},

{
    "rule_id": "RAG_UNTRUSTED_RETRIEVAL",
    "title": "RAG Untrusted Retrieval Source",
    "patterns": [
        r"retriever\.add_documents\(.*user",
        r"vectorstore\.add_documents\(.*user",
        r"load_documents\(.*external",
        r"untrusted_retrieval",
    ],
    "severity": "High",
    "vuln_type": "rag_untrusted_retrieval",
},
{
    "rule_id": "RAG_NO_SOURCE_GROUNDING",
    "title": "RAG Missing Source Grounding",
    "patterns": [
        r"return\s+answer\s*$",
        r"source_required\s*=\s*False",
        r"citations_required\s*=\s*False",
        r"without_source_grounding",
    ],
    "severity": "Medium",
    "vuln_type": "rag_no_source_grounding",
},
{
    "rule_id": "MEMORY_PERSISTENCE_RISK",
    "title": "AI Memory Persistence Risk",
    "patterns": [
        r"memory\.save_context",
        r"persistent_memory\s*=\s*True",
        r"store_user_memory",
        r"save_chat_history",
    ],
    "severity": "High",
    "vuln_type": "ai_memory_persistence",
},
{
    "rule_id": "MEMORY_CROSS_TENANT_LEAKAGE",
    "title": "AI Memory Cross-Tenant Leakage Risk",
    "patterns": [
        r"global_memory",
        r"shared_memory",
        r"tenant_id\s*=\s*None",
        r"cross_tenant_memory",
    ],
    "severity": "Critical",
    "vuln_type": "ai_memory_cross_tenant_leakage",
},
{
    "rule_id": "TOOL_APPROVAL_BYPASS",
    "title": "AI Tool Approval Bypass",
    "patterns": [
        r"approval_required\s*=\s*False",
        r"human_approval\s*=\s*False",
        r"skip_approval\s*=\s*True",
        r"auto_approve\s*=\s*True",
    ],
    "severity": "Critical",
    "vuln_type": "ai_tool_approval_bypass",
},
{
    "rule_id": "AUTONOMOUS_TOOL_EXECUTION",
    "title": "Autonomous Tool Execution Risk",
    "patterns": [
        r"run_shell\s*=\s*True",
        r"shell\.exec",
        r"tool\.run\(.*user",
        r"os\.system\(.*user",
    ],
    "severity": "Critical",
    "vuln_type": "ai_autonomous_tool_execution",
},
{
    "rule_id": "EMBEDDING_DATA_EXPOSURE",
    "title": "Embedding Data Exposure Risk",
    "patterns": [
        r"dump_embeddings",
        r"export_embeddings",
        r"embedding_store\.dump",
        r"vectorstore\.persist",
    ],
    "severity": "High",
    "vuln_type": "embedding_data_exposure",
},
{
    "rule_id": "MODEL_GOVERNANCE_MISSING_OWNER",
    "title": "Model Governance Missing Owner",
    "patterns": [
        r"model_owner\s*=\s*None",
        r"owner\s*=\s*\"\"",
        r"missing_model_owner",
    ],
    "severity": "Medium",
    "vuln_type": "model_governance_missing_owner",
},
{
    "rule_id": "MODEL_GOVERNANCE_MISSING_MODEL_CARD",
    "title": "Model Governance Missing Model Card",
    "patterns": [
        r"model_card\s*=\s*None",
        r"model_card_required\s*=\s*False",
        r"missing_model_card",
    ],
    "severity": "Medium",
    "vuln_type": "model_governance_missing_model_card",
},

{
    "rule_id": "RAG_POISONING",
    "title": "RAG Poisoning Risk",
    "patterns": [
        r"retriever\.add_documents\(.*user",
        r"vectorstore\.add_documents\(.*user",
        r"rag_poisoning",
        r"untrusted_documents",
    ],
    "severity": "High",
    "vuln_type": "rag_poisoning",
},
{
    "rule_id": "SOURCE_GROUNDING_MISSING",
    "title": "Source Grounding Missing",
    "patterns": [
        r"source_required\s*=\s*False",
        r"citations_required\s*=\s*False",
        r"without_source_grounding",
        r"return\s+answer\s*$",
        r"source_grounding_missing\s*=\s*True",
        ],
    "severity": "Medium",
    "vuln_type": "source_grounding_missing",
},
{
    "rule_id": "UNSAFE_FUNCTION_CALLING",
    "title": "Unsafe Function Calling",
    "patterns": [
        r"function_call\s*=\s*[\"']auto[\"']",
        r"tool_choice\s*=\s*[\"']auto[\"']",
        r"allow_arbitrary_input\s*=\s*True",
        r"execute_function\(.*user",
    ],
    "severity": "High",
    "vuln_type": "unsafe_function_calling",
},
{
    "rule_id": "UNSAFE_AUTONOMOUS_DECISION",
    "title": "Unsafe Autonomous Decision",
    "patterns": [
        r"auto_execute_decision\s*=\s*True",
        r"autonomous_decision\s*=\s*True",
        r"decision_review_required\s*=\s*False",
    ],
    "severity": "High",
    "vuln_type": "unsafe_autonomous_decision",
},
{
    "rule_id": "NO_HUMAN_REVIEW",
    "title": "No Human Review for AI Decision",
    "patterns": [
        r"human_review_required\s*=\s*False",
        r"human_in_the_loop\s*=\s*False",
        r"skip_human_review\s*=\s*True",
    ],
    "severity": "High",
    "vuln_type": "no_human_review",
},
{
    "rule_id": "SYSTEM_PROMPT_EXPOSURE",
    "title": "System Prompt Exposure",
    "patterns": [
        r"print\(.*system[_-]?prompt",
        r"return.*system[_-]?prompt",
        r"system[_-]?prompt.*response",
        r"expose_system_prompt",
    ],
    "severity": "Critical",
    "vuln_type": "system_prompt_exposure",
},
{
    "rule_id": "PROMPT_TEMPLATE_SECRET_EXPOSURE",
    "title": "Prompt Template Secret Exposure",
    "patterns": [
        r"prompt_template.*api[_-]?key",
        r"prompt_template.*secret",
        r"template.*password",
        # D2 (2026-10-17, diffusers): ``template.*token`` must see a
        # CREDENTIAL token, not the tokenization vocabulary -- the window
        # matched ``apply_chat_template(messages, tokenize=False, ...)`` and
        # the identifier ``_PROMPT_TEMPLATE_ENCODE_NUM_SUFFIX_TOKENS`` (a
        # token COUNT).  Same word boundary B7a applied on the secrets side.
        r"template.*token(?![A-Za-z])",
    ],
    "severity": "Critical",
    "vuln_type": "prompt_template_secret_exposure",
},
{
    "rule_id": "MODEL_GOVERNANCE_INCOMPLETE",
    "title": "Model Governance Incomplete",
    "patterns": [
        r"model_owner\s*=\s*None",
        r"model_card\s*=\s*None",
        r"model_approval\s*=\s*False",
        r"governance_review\s*=\s*False",
    ],
    "severity": "Medium",
    "vuln_type": "model_governance_incomplete",
},
{
    "rule_id": "UNSIGNED_OR_UNTRUSTED_MODEL_LOADING",
    "title": "Unsigned or Untrusted Model Loading",
    "patterns": [
        r"torch\.load\(.*http",
        r"load_model\(.*http",
        r"from_pretrained\(.*trust_remote_code\s*=\s*True",
        r"untrusted_model_source",
    ],
    "severity": "High",
    "vuln_type": "unsigned_or_untrusted_model_loading",
},
{
    "rule_id": "PROMPT_RESPONSE_LOGGING_SENSITIVE_DATA",
    "title": "Prompt Response Logging Sensitive Data",
    "patterns": [
        r"log.*prompt",
        r"log.*response",
        r"logger.*api[_-]?key",
        r"logger.*secret",
    ],
    "severity": "High",
    "vuln_type": "prompt_response_logging_sensitive_data",
},





{
    "rule_id": "UNTRUSTED_MODEL_LOADING",
    "title": "Untrusted Model Loading",
    "patterns": [
        r"torch\.load\(.*http",
        r"load_model\(.*http",
        r"from_pretrained\(.*trust_remote_code\s*=\s*True",
        r"untrusted_model_source",
            r"untrusted_model_loading\s*=\s*True"
        ],
    "severity": "High",
    "vuln_type": "untrusted_model_loading",
},


{
    "rule_id": "DATA_UNTRUSTED_TRAINING_UPLOAD",
    "title": "Untrusted Training Data Upload",
    "patterns": [
        r"untrusted_user_training_upload",
        r"external_dataset",
        r"user_uploaded_training_data",
        r"train_model\(.*user",
    ],
    "severity": "High",
    "vuln_type": "ai_data_lineage_risk",
},

{
    "rule_id": "REG_MODEL_CHECKSUM_MISSING",
    "title": "Model Registry Checksum Missing",
    "patterns": [
        r"no_checksum_verification",
        r"checksum\s*=\s*None",
        r"verify_checksum\s*=\s*False",
        r"skip_checksum\s*=\s*True",
    ],
    "severity": "Critical",
    "vuln_type": "model_registry_integrity_risk",
},
{
    "rule_id": "AGENT_BROWSER_AUTOMATION_ABUSE",
    "title": "Agent Browser Automation Abuse",
    "patterns": [
        r"browser_automation_abuse",
        r"browser\.open\(.*user",
        r"page\.goto\(.*user",
        r"playwright.*user",
    ],
    "severity": "Critical",
    "vuln_type": "agent_browser_automation_abuse",
},
{
    "rule_id": "AGENT_EMAIL_EXFILTRATION",
    "title": "Agent Email Exfiltration Risk",
    "patterns": [
        r"email_exfiltration",
        r"send_email\(.*secret",
        r"smtp.*exfiltrate",
        r"mail.*token",
    ],
    "severity": "Critical",
    "vuln_type": "agent_email_exfiltration",
},
{
    "rule_id": "PSC_PROMPT_SIGNING_MISSING",
    "title": "Prompt Supply Chain Signing Missing",
    "patterns": [
        r"prompt_signing_missing",
        r"verify_prompt_signature\s*=\s*False",
        r"prompt_signature\s*=\s*None",
        r"unsigned_prompt_template",
    ],
    "severity": "Critical",
    "vuln_type": "prompt_supply_chain_signing_missing",
},
{
    "rule_id": "VDB_VECTOR_DB_EXPOSURE",
    "title": "Vector Database Exposure",
    "patterns": [
        r"vector_db_exposure",
        r"qdrant.*api_key\s*=",
        r"pinecone.*api_key\s*=",
        r"weaviate.*anonymous",
        r"chroma_server_host\s*=\s*[\"']0\.0\.0\.0",
    ],
    "severity": "High",
    "vuln_type": "vector_database_exposure",
},
{
    "rule_id": "RUN_UNSAFE_RUNTIME_TOOL",
    "title": "Unsafe Runtime Tool Execution",
    "patterns": [
        r"unsafe_runtime_tool",
        r"runtime_tool.*shell",
        r"execute_runtime_tool\(.*user",
        r"tool_runtime_approval\s*=\s*False",
    ],
    "severity": "Critical",
    "vuln_type": "unsafe_runtime_tool_execution",
},
{
    "rule_id": "GOV_MODEL_APPROVAL_MISSING",
    "title": "Model Approval Missing",
    "patterns": [
        r"model_approval_missing",
        r"model_approval\s*=\s*False",
        r"governance_review\s*=\s*False",
        r"approval_status\s*=\s*[\"']none[\"']",
    ],
    "severity": "Medium",
    "vuln_type": "model_approval_missing",
},
{
    "rule_id": "COMP_AI_POLICY_MISSING",
    "title": "AI Policy Compliance Missing",
    "patterns": [
        r"ai_policy_missing",
        r"policy_check\s*=\s*False",
        r"compliance_check\s*=\s*False",
        r"risk_assessment\s*=\s*None",
    ],
    "severity": "Medium",
    "vuln_type": "ai_policy_compliance_missing",
},
{
    "rule_id": "AI_PROVIDER_SECRET_EXPOSURE",
    "title": "AI Provider Secret Exposure",
    "patterns": [
        r"OPENAI_API_KEY\s*=",
        r"ANTHROPIC_API_KEY\s*=",
        r"VERTEX_AI_KEY\s*=",
        r"GOOGLE_APPLICATION_CREDENTIALS",
        r"AZURE_OPENAI_API_KEY\s*=",
    ],
    "severity": "Critical",
    "vuln_type": "ai_provider_secret_exposure",
},

]



# Compile regexes once; one alternation per rule reduces repeated regex calls.
for _rule in LLM_RULES:
    _patterns = _rule.get("patterns", [])
    _rule["_compiled_patterns"] = [re.compile(p, re.IGNORECASE) for p in _patterns]
    _rule["_combined_pattern"] = (
        re.compile("|".join(f"(?:{p})" for p in _patterns), re.IGNORECASE)
        if _patterns else None
    )


# Enterprise remediation metadata for LLM / Agentic AI findings.
# This prevents reports from falling back to generic text such as
# "Follow secure coding best practices" and gives engineers actionable fixes.
#
# The OWASP GenAI edition catalogues and the vulnerability-type -> entry
# tables live in core/owasp_mappings.py so there is exactly one source of
# truth for every OWASP label V11 emits.  That module's docstring records the
# two primary sources and why both the 2025 and 2026 namespaces travel with
# every finding.


def _owasp_llm_reference(rule_id: str, vuln_type: str) -> dict:
    """Edition-tagged OWASP GenAI reference for a finding rule."""
    return _core_owasp_llm_reference(vuln_type)


def _owasp_llm(rule_id: str, vuln_type: str) -> str:
    return _owasp_llm_reference(rule_id, vuln_type)["owasp"]


CWE_MAP = {
    "llm_prompt_injection": "CWE-20",
    "llm_insecure_output": "CWE-94",
    "llm_sensitive_disclosure": "CWE-200",
    "system_prompt_exposure": "CWE-200",
    "prompt_template_secret_exposure": "CWE-798",
    "prompt_response_logging_sensitive_data": "CWE-532",
    "llm_insecure_plugin": "CWE-749",
    "llm_excessive_agency": "CWE-269",
    "ai_autonomous_tool_execution": "CWE-78",
    "ai_tool_approval_bypass": "CWE-306",
    "unsafe_function_calling": "CWE-20",
    "unsafe_runtime_tool_execution": "CWE-78",
    "unsafe_autonomous_decision": "CWE-840",
    "no_human_review": "CWE-840",
    "rag_poisoning": "CWE-20",
    "rag_untrusted_retrieval": "CWE-20",
    "source_grounding_missing": "CWE-345",
    "rag_no_source_grounding": "CWE-345",
    "embedding_data_exposure": "CWE-200",
    "vector_database_exposure": "CWE-200",
    "ai_memory_persistence": "CWE-359",
    "ai_memory_cross_tenant_leakage": "CWE-200",
    "model_governance_missing_owner": "CWE-1059",
    "model_governance_missing_model_card": "CWE-1059",
    "model_governance_incomplete": "CWE-1059",
    "model_approval_missing": "CWE-1059",
    "ai_policy_compliance_missing": "CWE-1059",
    "unsigned_or_untrusted_model_loading": "CWE-494",
    "untrusted_model_loading": "CWE-494",
    "model_registry_integrity_risk": "CWE-353",
    "llm_model_theft": "CWE-200",
    "agent_browser_automation_abuse": "CWE-918",
    "agent_email_exfiltration": "CWE-200",
    "prompt_supply_chain_signing_missing": "CWE-347",
    "ai_provider_secret_exposure": "CWE-798",
    "ai_data_lineage_risk": "CWE-345",
    "llm_data_poisoning": "CWE-345",
    "llm_model_dos": "CWE-400",
    "llm_supply_chain": "CWE-1104",
    "llm_overreliance": "CWE-840",
}

DEFAULT_LLM_REMEDIATION = [
    "Perform threat modeling for the affected AI workflow and identify user-controlled inputs, tool calls, model outputs, and downstream actions.",
    "Apply least privilege to model, agent, tool, data, and runtime permissions.",
    "Add validation, logging, monitoring, and human review for high-risk AI decisions or actions.",
]

REMEDIATION_BY_VULN_TYPE = {
    "ai_autonomous_tool_execution": [
        "Require explicit human approval before executing shell, file, network, cloud, or deployment tools.",
        "Restrict agent tools using an allow-list of approved commands and approved target resources.",
        "Block direct shell execution such as shell.exec unless routed through a controlled broker.",
        "Run tools in a sandbox with least-privilege permissions, timeout limits, and audit logging.",
        "Validate tool arguments to prevent command injection, file deletion, data exfiltration, or privilege escalation.",
    ],
    "llm_insecure_plugin": [
        "Require authentication, authorization, and scope checks before any plugin or tool action executes.",
        "Use a tool allow-list and deny direct access to shell, browser, file system, deployment, and credential operations by default.",
        "Validate and normalize plugin parameters before execution; reject user-controlled command strings.",
        "Run plugins in an isolated sandbox with network, file, and process restrictions.",
        "Log tool requests, approvals, parameters, and execution results for audit and incident response.",
    ],
    "llm_insecure_output": [
        "Never execute LLM output directly using eval(), exec(), shell commands, subprocess, or dynamic code loaders.",
        "Treat all model output as untrusted input and validate it against a strict schema.",
        "Use deterministic allow-listed actions instead of free-form model-generated commands.",
        "Add output filtering for unsafe code, shell metacharacters, secrets, URLs, and sensitive operations.",
        "Require human approval for high-risk actions such as command execution, file writes, deployment, or data deletion.",
    ],
    "llm_sensitive_disclosure": [
        "Do not place secrets, credentials, system prompts, internal policy, or privileged instructions in user-visible model context.",
        "Redact secrets and sensitive headers before sending prompts or logs to model providers.",
        "Separate system prompts from user-controlled content and prevent prompt concatenation without boundaries.",
        "Add response filtering to block disclosure of secrets, tokens, credentials, internal URLs, or system prompts.",
        "Disable prompt/response logging for sensitive data or apply irreversible redaction before storage.",
    ],
    "system_prompt_exposure": [
        "Do not concatenate system prompts directly with user input.",
        "Store system prompts server-side and never return them in API responses, logs, or debug traces.",
        "Use role-separated message structures instead of raw prompt string concatenation.",
        "Add prompt-injection checks for requests asking to reveal instructions, policies, secrets, or hidden context.",
        "Monitor and alert on repeated attempts to extract system prompts or internal instructions.",
    ],
    "prompt_response_logging_sensitive_data": [
        "Disable prompt and response logging for sensitive workflows unless a documented business need exists.",
        "Apply irreversible redaction for secrets, tokens, PII, authentication headers, and system prompts before storage.",
        "Restrict log access using least privilege and separate duties for operations, developers, and support teams.",
        "Set log retention limits and encrypt logs at rest and in transit.",
        "Add automated scanning to detect sensitive data in prompt/response logs.",
    ],
    "prompt_template_secret_exposure": [
        "Remove credentials, tokens, passwords, API keys, and private configuration values from prompt templates.",
        "Resolve secrets at runtime from a secrets manager and never inject raw secret values into prompts.",
        "Review prompt templates before release and scan them using secret-detection controls.",
        "Separate business instructions from sensitive configuration and credential material.",
        "Rotate any credential that may have been stored in prompt templates or prompt history.",
    ],
    "ai_provider_secret_exposure": [
        "Remove AI provider API keys from source code, config files, prompts, and logs.",
        "Store provider credentials in a secrets manager and inject them only at runtime.",
        "Rotate exposed provider keys immediately and review provider audit logs for misuse.",
        "Restrict provider keys by project, environment, model, IP range, and usage quota where supported.",
        "Add pre-commit and CI secret scanning to prevent future exposure.",
    ],
    "ai_tool_approval_bypass": [
        "Re-enable human approval for high-risk tools and privileged actions.",
        "Define approval policies by action type, target resource, data sensitivity, and environment.",
        "Prevent user input from disabling approval flags such as approval_required or human_approval.",
        "Record approver identity, request context, parameters, and execution outcome.",
        "Add tests that fail when approval gates are bypassed for sensitive tools.",
    ],
    "unsafe_function_calling": [
        "Disable unrestricted auto function calling for sensitive operations.",
        "Use a strict JSON schema for tool/function arguments and reject unknown fields.",
        "Apply server-side authorization for each function call independent of the model decision.",
        "Allow only pre-approved functions and block arbitrary function names or user-controlled dispatch.",
        "Require human review for functions that modify data, invoke external systems, or access sensitive records.",
    ],
    "unsafe_runtime_tool_execution": [
        "Route runtime tool execution through a controlled broker instead of direct shell/runtime access.",
        "Block arbitrary command strings and accept only structured, validated action parameters.",
        "Run runtime tools in isolated containers with read-only file systems and restricted network access.",
        "Apply timeouts, resource limits, and output-size limits for all runtime tools.",
        "Log all tool invocations, approvals, parameters, and outputs for traceability.",
    ],
    "unsafe_autonomous_decision": [
        "Require human-in-the-loop review for business-critical or user-impacting AI decisions.",
        "Define policy gates for autonomous decisions based on risk, data sensitivity, and financial or operational impact.",
        "Add deterministic validation checks before executing model-selected decisions.",
        "Record decision rationale, input data, model version, and reviewer approval where applicable.",
        "Provide rollback and override controls for incorrect autonomous decisions.",
    ],
    "no_human_review": [
        "Add mandatory human review for high-impact AI decisions, privileged operations, and sensitive data actions.",
        "Define escalation paths for uncertain, low-confidence, or policy-sensitive model outputs.",
        "Record reviewer identity, decision, timestamp, and reason for approval or rejection.",
        "Block automated execution when required review metadata is missing.",
        "Test that human review cannot be disabled by user-controlled input or configuration drift.",
    ],
    "llm_prompt_injection": [
        "Separate system, developer, retrieved, and user content using role-aware message boundaries.",
        "Treat retrieved documents and user prompts as untrusted input and never let them override system instructions.",
        "Add prompt-injection detection for requests to ignore instructions, reveal hidden prompts, or bypass policy.",
        "Constrain model actions with server-side authorization and tool allow-lists rather than prompt instructions alone.",
        "Log and monitor prompt-injection attempts and test known jailbreak patterns during release validation.",
    ],
    "rag_poisoning": [
        "Validate document source, ownership, and integrity before adding content to the retrieval index.",
        "Separate trusted enterprise content from user-submitted or internet-sourced content.",
        "Require source citations and confidence checks before using retrieved content in answers or actions.",
        "Scan retrieved documents for prompt-injection instructions and malicious tool-use instructions.",
        "Maintain versioned indexes and rollback capability for poisoned or untrusted documents.",
    ],
    "rag_untrusted_retrieval": [
        "Restrict retrieval ingestion to approved, authenticated, and integrity-checked sources.",
        "Tag documents by trust level and prevent low-trust content from driving privileged actions.",
        "Sanitize retrieved content before injecting it into model context.",
        "Require source attribution for retrieved answers and block answers without acceptable sources.",
        "Monitor retrieval index changes and alert on unusual bulk ingestion or external-source spikes.",
    ],
    "source_grounding_missing": [
        "Require citations or source identifiers for RAG-generated answers.",
        "Block high-confidence responses when no trusted source supports the answer.",
        "Return an explicit insufficient-evidence response when retrieval confidence is low.",
        "Store source IDs with generated responses for auditability.",
        "Evaluate grounding quality during testing using adversarial and out-of-domain prompts.",
    ],
    "rag_no_source_grounding": [
        "Require citations or source identifiers for RAG-generated answers.",
        "Block high-confidence responses when no trusted source supports the answer.",
        "Return an explicit insufficient-evidence response when retrieval confidence is low.",
        "Store source IDs with generated responses for auditability.",
        "Evaluate grounding quality during testing using adversarial and out-of-domain prompts.",
    ],
    "embedding_data_exposure": [
        "Do not export or dump embeddings unless approved and encrypted.",
        "Treat embeddings as sensitive derived data when they can reveal source text, users, or business context.",
        "Restrict vector-store persistence and backups using least privilege and encryption.",
        "Apply tenant isolation to embedding stores and delete embeddings when source data is deleted.",
        "Monitor bulk export, dump, or persistence operations from embedding stores.",
    ],
    "vector_database_exposure": [
        "Require authentication and network restrictions for vector database endpoints.",
        "Disable anonymous access and avoid binding vector databases to 0.0.0.0 unless behind protected infrastructure.",
        "Store vector database API keys in a secrets manager and rotate exposed keys.",
        "Apply tenant-level access controls and encryption for vector collections.",
        "Monitor query, export, and collection-management operations for abnormal access.",
    ],
    "ai_memory_persistence": [
        "Persist AI memory only with explicit user, tenant, and purpose boundaries.",
        "Avoid storing secrets, credentials, regulated data, or sensitive conversation content in long-term memory.",
        "Encrypt memory stores and enforce tenant isolation and retention limits.",
        "Provide deletion, review, and consent controls for persisted memory.",
        "Audit memory reads/writes and alert on cross-user or cross-tenant access patterns.",
    ],
    "ai_memory_cross_tenant_leakage": [
        "Partition memory by tenant and user using enforced server-side authorization checks.",
        "Remove global/shared memory for tenant-specific data unless strong isolation is implemented.",
        "Include tenant_id in memory keys and queries; reject operations without tenant context.",
        "Add tests proving one tenant cannot retrieve another tenant's memory.",
        "Encrypt tenant memory separately and monitor cross-tenant access attempts.",
    ],
    "llm_data_poisoning": [
        "Accept training data only from approved, authenticated, and integrity-checked sources.",
        "Track data lineage, uploader identity, license, timestamp, and approval status for every dataset.",
        "Scan training data for malicious instructions, secrets, sensitive data, and outlier content.",
        "Separate staging and production training datasets with review and approval gates.",
        "Keep dataset versions and rollback capability for poisoned or low-quality data.",
    ],
    "ai_data_lineage_risk": [
        "Track dataset source, owner, license, consent, approval status, and transformation history.",
        "Block user-uploaded training data from production training until reviewed and approved.",
        "Scan incoming datasets for secrets, regulated data, malicious prompts, and policy violations.",
        "Maintain immutable dataset versions for audit and rollback.",
        "Document data retention, deletion, and opt-out handling for training inputs.",
    ],
    "unsigned_or_untrusted_model_loading": [
        "Load models only from approved registries or trusted internal artifact stores.",
        "Verify model signatures, checksums, and provenance before loading.",
        "Disable trust_remote_code unless reviewed and explicitly approved.",
        "Run new or third-party models in a sandbox before production deployment.",
        "Record model source, version, digest, owner, and approval status in the model inventory.",
    ],
    "untrusted_model_loading": [
        "Load models only from approved registries or trusted internal artifact stores.",
        "Verify model signatures, checksums, and provenance before loading.",
        "Disable trust_remote_code unless reviewed and explicitly approved.",
        "Run new or third-party models in a sandbox before production deployment.",
        "Record model source, version, digest, owner, and approval status in the model inventory.",
    ],
    "model_registry_integrity_risk": [
        "Require checksum verification before model download, loading, or deployment.",
        "Store approved model checksums and signatures in a controlled model registry.",
        "Block model promotion when checksum, signature, or provenance metadata is missing.",
        "Audit registry changes and alert on model replacement or checksum drift.",
        "Include model digest, version, source, owner, and approval status in release evidence.",
    ],
    "llm_model_theft": [
        "Restrict model export, checkpoint copying, and weight download permissions to approved roles.",
        "Encrypt model artifacts at rest and in transit and monitor bulk download behavior.",
        "Disable debug endpoints or admin APIs that expose model weights or embeddings.",
        "Watermark or fingerprint proprietary models where feasible.",
        "Alert on model export, checkpoint copy, save_pretrained, or unusual artifact access events.",
    ],
    "agent_browser_automation_abuse": [
        "Restrict browser automation to approved domains and block user-controlled navigation to arbitrary URLs.",
        "Run browser automation in a sandboxed profile with no persistent credentials unless explicitly required.",
        "Prevent agents from submitting forms, downloading files, or accessing internal URLs without approval.",
        "Validate URLs against allow-lists and block localhost, metadata services, and private network ranges.",
        "Capture audit logs and screenshots for sensitive browser automation actions.",
    ],
    "agent_email_exfiltration": [
        "Require human approval before an agent sends email or attaches files.",
        "Block sending secrets, tokens, credentials, or regulated data to external recipients.",
        "Apply recipient allow-lists, DLP scanning, and content redaction before email dispatch.",
        "Use a dedicated low-privilege service account for agent email actions.",
        "Log recipient, subject, attachments, approval status, and DLP outcome for audit.",
    ],
    "prompt_supply_chain_signing_missing": [
        "Sign prompt templates and verify signatures before runtime use.",
        "Store prompt templates in a controlled repository with code review and change approval.",
        "Block unsigned or modified prompt templates from production deployment.",
        "Track prompt template owner, version, checksum, and deployment history.",
        "Alert on prompt template signature failures or unexpected prompt changes.",
    ],
    "model_governance_missing_owner": [
        "Assign a named business owner and technical owner for the model.",
        "Record owner, purpose, risk tier, data sources, and approval status in the model inventory.",
        "Block production release when model ownership metadata is missing.",
    ],
    "model_governance_missing_model_card": [
        "Create and maintain a model card covering purpose, limitations, datasets, risks, evaluation results, and approved use cases.",
        "Require model card review before promotion to production.",
        "Update the model card when data, model version, risk profile, or deployment context changes.",
    ],
    "model_governance_incomplete": [
        "Complete model ownership, model card, approval, and governance review metadata before release.",
        "Define model risk tier, intended use, prohibited use, data classification, and monitoring requirements.",
        "Block production deployment until governance approval is recorded.",
    ],
    "model_approval_missing": [
        "Require documented model approval before production use.",
        "Record approver, approval date, model version, evaluation evidence, and release scope.",
        "Block deployments with approval_status missing, none, or false.",
    ],
    "ai_policy_compliance_missing": [
        "Add an AI policy compliance check before release.",
        "Validate data use, model purpose, privacy, safety, security, and regulatory requirements.",
        "Record compliance evidence and risk acceptance decisions in the release package.",
    ],
    "llm_model_dos": [
        "Set maximum token, input length, output length, concurrency, and request-rate limits.",
        "Reject unbounded loops, recursive agent calls, and excessive tool invocation chains.",
        "Apply per-user and per-tenant quotas for model usage.",
        "Add timeout and circuit-breaker controls for model and tool calls.",
        "Monitor abnormal token consumption, latency, and repeated failed requests.",
    ],
    "llm_supply_chain": [
        "Pin AI framework and model dependency versions and verify package integrity.",
        "Use approved package registries and block untrusted model downloads.",
        "Generate SBOM/AI-BOM evidence for AI dependencies, models, plugins, and tools.",
        "Review third-party AI libraries for known CVEs, malicious packages, and license risk.",
        "Require provenance, checksum, and approval metadata for external models and plugins.",
    ],
    "llm_overreliance": [
        "Do not accept model output without validation for security, financial, legal, or user-impacting decisions.",
        "Use deterministic rules and independent checks for critical decisions.",
        "Display uncertainty and require human review for low-confidence outputs.",
        "Test model outputs against adversarial, edge-case, and policy-sensitive scenarios.",
        "Log decisions and validation outcomes for audit and continuous improvement.",
    ],
}

DESCRIPTION_BY_VULN_TYPE = {
    "ai_autonomous_tool_execution": "Agent or LLM workflow can invoke tools such as shell, file, browser, network, or deployment actions without sufficient approval or restriction.",
    "llm_insecure_plugin": "Plugin or tool interface can execute sensitive operations without strong authorization, parameter validation, or sandboxing.",
    "llm_insecure_output": "Model output is used in executable code, shell, subprocess, or dynamic evaluation paths without validation.",
    "llm_sensitive_disclosure": "Sensitive information may be exposed through prompts, responses, logs, memory, or model context.",
    "system_prompt_exposure": "System prompts or privileged model instructions may be exposed or mixed with user-controlled content.",
    "prompt_response_logging_sensitive_data": "Prompts or responses may be logged with secrets, credentials, tokens, or sensitive data.",
    "prompt_template_secret_exposure": "Prompt templates may contain secrets, credentials, tokens, or sensitive configuration values.",
    "ai_provider_secret_exposure": "AI provider credentials are present in code, configuration, prompt context, or logs.",
    "ai_tool_approval_bypass": "Tool approval controls can be disabled or bypassed, enabling sensitive actions without review.",
    "unsafe_function_calling": "Function or tool calling allows auto-dispatch or arbitrary user-controlled execution paths.",
    "unsafe_runtime_tool_execution": "Runtime tool execution may allow shell or privileged runtime operations from untrusted input.",
    "unsafe_autonomous_decision": "AI workflow can make or execute business-impacting decisions without sufficient review or deterministic controls.",
    "no_human_review": "High-risk AI decision path does not require human review or documented approval.",
    "llm_prompt_injection": "User-controlled or retrieved content may override, bypass, or manipulate model instructions.",
    "rag_poisoning": "Untrusted content can enter the retrieval corpus and influence model output or downstream actions.",
    "rag_untrusted_retrieval": "RAG workflow retrieves or ingests content from untrusted sources without trust boundaries or validation.",
    "source_grounding_missing": "Generated answers are not required to cite or ground output in trusted sources.",
    "rag_no_source_grounding": "RAG output is not required to cite or ground answers in trusted retrieved evidence.",
    "embedding_data_exposure": "Embeddings or vector-store data may be exported, persisted, or exposed without adequate controls.",
    "vector_database_exposure": "Vector database endpoint or credentials may be exposed or insufficiently access controlled.",
    "ai_memory_persistence": "Long-term AI memory may persist sensitive data without clear retention, consent, or tenant controls.",
    "ai_memory_cross_tenant_leakage": "Shared or global AI memory can leak data across users or tenants.",
    "llm_data_poisoning": "Training or fine-tuning data can be influenced by untrusted or unreviewed sources.",
    "ai_data_lineage_risk": "Training data lacks sufficient lineage, approval, or integrity controls.",
    "unsigned_or_untrusted_model_loading": "Model loading path trusts external or unsigned model artifacts.",
    "untrusted_model_loading": "Model loading path trusts external or unapproved model artifacts.",
    "model_registry_integrity_risk": "Model registry or artifact loading lacks checksum/signature verification.",
    "llm_model_theft": "Model weights, checkpoints, embeddings, or proprietary artifacts may be exported or copied without sufficient controls.",
    "agent_browser_automation_abuse": "Agent-controlled browser automation may access arbitrary URLs or perform sensitive actions without restrictions.",
    "agent_email_exfiltration": "Agent email capability may send secrets or sensitive data outside approved boundaries.",
    "prompt_supply_chain_signing_missing": "Prompt templates are not signed or integrity-verified before runtime use.",
    "model_governance_missing_owner": "Model ownership metadata is missing, weakening accountability and release governance.",
    "model_governance_missing_model_card": "Model card documentation is missing, weakening transparency and risk review.",
    "model_governance_incomplete": "Model governance metadata, approval, or documentation is incomplete.",
    "model_approval_missing": "Model approval status is missing or disabled before release.",
    "ai_policy_compliance_missing": "AI workflow lacks documented policy or compliance review before release.",
    "llm_model_dos": "AI workflow may allow excessive token usage, unbounded execution, or resource exhaustion.",
    "llm_supply_chain": "AI dependency, model, plugin, or framework supply chain controls are insufficient.",
    "llm_overreliance": "Model output may be accepted without independent validation for sensitive decisions.",
}

BUSINESS_IMPACT_BY_VULN_TYPE = {
    "ai_autonomous_tool_execution": "Unauthorized autonomous tool execution can cause data deletion, command execution, cloud changes, data exfiltration, and production impact.",
    "llm_insecure_plugin": "Insecure plugins can become an execution bridge from prompt input to privileged systems, enabling unauthorized actions and data exposure.",
    "llm_insecure_output": "Executing model output can lead to remote code execution, command injection, data theft, or unsafe business actions.",
    "llm_sensitive_disclosure": "Sensitive information disclosure can expose credentials, internal instructions, customer data, or regulated information.",
    "system_prompt_exposure": "System prompt disclosure can reveal internal controls and make prompt injection or policy bypass easier.",
    "prompt_response_logging_sensitive_data": "Sensitive prompt/response logs can create long-lived data exposure and audit/compliance risk.",
    "prompt_template_secret_exposure": "Secrets in prompt templates can leak to users, providers, logs, or model memory and require credential rotation.",
    "ai_provider_secret_exposure": "Exposed AI provider keys can enable unauthorized model usage, data access, cost abuse, and provider account compromise.",
    "ai_tool_approval_bypass": "Bypassed tool approval can allow unreviewed privileged operations and weaken release governance.",
    "unsafe_function_calling": "Unsafe function calling can let model or user-controlled input trigger unauthorized business operations.",
    "unsafe_runtime_tool_execution": "Unsafe runtime tools can enable arbitrary command execution, data exfiltration, or environment compromise.",
    "unsafe_autonomous_decision": "Unreviewed autonomous decisions can cause financial, operational, legal, or customer harm.",
    "no_human_review": "Missing human review weakens accountability for high-impact AI actions and can violate governance expectations.",
    "llm_prompt_injection": "Prompt injection can bypass controls, disclose hidden context, or manipulate tool actions and responses.",
    "rag_poisoning": "Poisoned retrieval content can mislead users, trigger unsafe actions, or silently corrupt enterprise knowledge responses.",
    "rag_untrusted_retrieval": "Untrusted retrieval can introduce malicious instructions, inaccurate evidence, or data leakage paths.",
    "source_grounding_missing": "Ungrounded answers can produce unsupported recommendations and weaken auditability.",
    "rag_no_source_grounding": "Ungrounded RAG answers can create unsupported business decisions and audit gaps.",
    "embedding_data_exposure": "Exposed embeddings can leak sensitive source data, user context, or proprietary business information.",
    "vector_database_exposure": "Vector database exposure can leak indexed knowledge, embeddings, and tenant-specific data.",
    "ai_memory_persistence": "Uncontrolled memory persistence can retain sensitive information beyond intended purpose or retention periods.",
    "ai_memory_cross_tenant_leakage": "Cross-tenant memory leakage can expose one customer or business unit's data to another.",
    "llm_data_poisoning": "Poisoned training data can degrade model behavior, introduce unsafe outputs, or create hidden backdoors.",
    "ai_data_lineage_risk": "Weak data lineage reduces trust in model outputs and creates compliance and rollback challenges.",
    "unsigned_or_untrusted_model_loading": "Untrusted models can introduce malicious code, backdoors, or unsafe behavior into production.",
    "untrusted_model_loading": "Untrusted models can introduce malicious code, backdoors, or unsafe behavior into production.",
    "model_registry_integrity_risk": "Missing artifact verification can allow model tampering or unauthorized replacement.",
    "llm_model_theft": "Model theft can expose proprietary IP, training investment, embeddings, and sensitive derived data.",
    "agent_browser_automation_abuse": "Browser automation abuse can access internal systems, perform unauthorized actions, or leak data through web workflows.",
    "agent_email_exfiltration": "Agent email misuse can exfiltrate secrets, customer data, or regulated information to unauthorized recipients.",
    "prompt_supply_chain_signing_missing": "Unsigned prompt templates can be modified without detection, changing model behavior or bypassing controls.",
    "model_governance_missing_owner": "Missing ownership weakens accountability for model risk, operation, and remediation.",
    "model_governance_missing_model_card": "Missing model cards reduce transparency, approval quality, and audit readiness.",
    "model_governance_incomplete": "Incomplete model governance can block production release and weaken enterprise AI assurance.",
    "model_approval_missing": "Missing model approval weakens release controls and audit evidence.",
    "ai_policy_compliance_missing": "Missing policy compliance review can create regulatory, privacy, security, and reputational risk.",
    "llm_model_dos": "Unbounded model usage can cause service degradation, cost spikes, and denial of service.",
    "llm_supply_chain": "Weak AI supply chain controls can introduce vulnerable packages, malicious models, or license risk.",
    "llm_overreliance": "Overreliance can cause incorrect, unsafe, or unsupported decisions without human or deterministic validation.",
}


def _remediation_for(vuln_type: str) -> list[str]:
    return list(REMEDIATION_BY_VULN_TYPE.get(vuln_type, DEFAULT_LLM_REMEDIATION))


def _description_for(vuln_type: str, title: str) -> str:
    return DESCRIPTION_BY_VULN_TYPE.get(vuln_type, f"{title} detected in AI/LLM workflow and requires security review.")


def _business_impact_for(vuln_type: str) -> str:
    return BUSINESS_IMPACT_BY_VULN_TYPE.get(
        vuln_type,
        "AI/LLM control weakness may enable unsafe model behavior, unauthorized action, sensitive data exposure, or governance failure.",
    )


# ---------------------------------------------------------------------------
# Rule-specific semantic aliases
# ---------------------------------------------------------------------------
# These aliases intentionally belong to the two generic rules whose
# canonical pattern families are otherwise semantically shadowed by their
# more specific counterparts.
RULE_SPECIFICITY_ALIASES = {
    "SOURCE_GROUNDING_MISSING": [
        r"source_grounding_missing",
    ],
    "UNTRUSTED_MODEL_LOADING": [
        r"untrusted_model_loading",
    ],
}

def _llm01_detection_view(line: str) -> str:
    """Detection-only normalization for OWASP LLM01 prompt-injection variants."""
    import unicodedata as _unicodedata

    value = str(line or "")

    def _decode(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    # Decode common source-level Unicode/hex escapes used to disguise tokens.
    value = re.sub(r"\\u([0-9a-fA-F]{4})", _decode, value)
    value = re.sub(r"\\U([0-9a-fA-F]{8})", _decode, value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", _decode, value)

    # Remove Unicode format/control characters such as zero-width space.
    value = "".join(
        ch for ch in value
        if _unicodedata.category(ch) != "Cf"
    )

    # Collapse fragmented quoted prompt pieces such as:
    # "ignore previous " + "instructions"
    value = re.sub(r"""(["'])\s*\+\s*(["'])""", " ", value)

    value = re.sub(r"\s+", " ", value).strip()
    return value


LLM01_ADDITIONAL_PATTERNS = (
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+previous\s+instructions",
    r"disregard\s+previous\s+instructions",
    r"ignora\s+las\s+instrucciones\s+anteriores",
    r"revela\s+las\s+instrucciones\s+del\s+sistema",
)
# ---------------------------------------------------------------------------
# V11 layered LLM01 / LLM02 evidence helpers
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# PERFORMANCE (G-134). Read the module-level note in _v11_llm01_detection_views.
# ---------------------------------------------------------------------------
_RX_CACHE: dict = {}


def _rx(pattern: str, flags: int = 0) -> "re.Pattern":
    """Compile once, reuse forever.

    The hot loops called re.search with a string pattern, so re's internal cache
    was consulted on every single call -- 591,613 times over a 40-file sample.
    """
    key = (pattern, flags)
    rx = _RX_CACHE.get(key)
    if rx is None:
        rx = re.compile(pattern, flags)
        _RX_CACHE[key] = rx
    return rx


_RX_ESC_U = re.compile(r"\\u([0-9a-fA-F]{4})")
_RX_ESC_BIGU = re.compile(r"\\U([0-9a-fA-F]{8})")
_RX_ESC_HEX = re.compile(r"\\x([0-9a-fA-F]{2})")
_RX_QUOTE_CONCAT = re.compile(r'(["\'])\s*\+\s*(["\'])')
_RX_WHITESPACE = re.compile(r"\s+")
_RX_B64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_RX_HEX_TOKEN = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")

_RX_SPLIT_INLINE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b[^\S\r\n]+"
    r"(previous|prior|system|developer|original|instructions)\b", re.IGNORECASE)
_RX_SPLIT_NEWLINE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b[^\S\r\n]*"
    r"(?:\r?\n|\r)+[^\S\r\n]*"
    r"\b(previous|prior|system|developer|original|instructions)\b", re.IGNORECASE)
_RX_SPLIT_SEPARATOR = re.compile(r"[\n\r+\\/_-]")
_RX_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Cyrillic and Greek homoglyphs. Moved from per-call construction to module level:
# str.maketrans built a fresh dict on every call, once per source line.
_CONFUSABLES = str.maketrans({
    chr(0x0430): "a", chr(0x0435): "e", chr(0x043E): "o",
    chr(0x0440): "p", chr(0x0441): "c", chr(0x0445): "x",
    chr(0x0456): "i", chr(0x03B1): "a", chr(0x03BF): "o",
    chr(0x03C1): "p", chr(0x03C4): "t", chr(0x03C7): "x",
})

_CF_TABLE: dict = {}


def _cf_table() -> dict:
    """Codepoints to delete for Unicode category 'Cf' (format).

    Built from unicodedata, not hardcoded: a hardcoded list is a hand
    transcription that goes stale against a Unicode version bump. Built once per
    process, and only when a transform could have introduced a format character,
    which is why it is lazy -- a scan of small files should not pay for it.
    """
    # `global` is required, not stylistic: assigning to _CF_TABLE inside this
    # function makes it local to the function for the WHOLE body, so without it
    # the read below raises UnboundLocalError on first call. That is a runtime
    # error, so py_compile accepts the module and only an actual scan surfaces it.
    global _CF_TABLE
    if not _CF_TABLE:
        import unicodedata as _u
        _CF_TABLE = {c: None for c in range(0x110000)
                     if _u.category(chr(c)) == "Cf"}
    return _CF_TABLE


def _v11_llm01_detection_views(text: str) -> dict:
    """Build detection-only views without changing the original evidence."""
    import base64 as _base64
    import html as _html
    import unicodedata as _unicodedata
    from urllib.parse import unquote as _unquote

    def _decode_escape(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, TypeError):
            return match.group(0)

    original = str(text or "")

    # NFKC is the identity on ASCII, so pure-ASCII input -- nearly every source
    # line -- skips normalisation entirely.
    plain_ascii = original.isascii()
    if plain_ascii:
        normalized = original
        zero_width_present = False
    else:
        normalized = _unicodedata.normalize("NFKC", original)
        zero_width_present = (
            len(normalized.translate(_cf_table())) != len(normalized))

    # Each transform can only alter the text when its own trigger character is
    # present. Testing for the trigger is a C-level scan; the transform is a regex
    # pass or a parser, so the test is far cheaper than the work it avoids. Order
    # is unchanged.
    if "\\" in normalized:
        normalized = _RX_ESC_U.sub(_decode_escape, normalized)
        normalized = _RX_ESC_BIGU.sub(_decode_escape, normalized)
        normalized = _RX_ESC_HEX.sub(_decode_escape, normalized)
    if "&" in normalized:
        normalized = _html.unescape(normalized)
    if "%" in normalized:
        normalized = _unquote(normalized)

    # The format-character strip stays LAST, and that is load-bearing rather than
    # cosmetic: decoding can PRODUCE a format character. "\\u00ad" yields SOFT
    # HYPHEN and "%EF%BB%BF" yields U+FEFF, both category Cf. A strip running
    # before the decodes would leave them in the text and change detection. So the
    # strip is skipped only when nothing could have introduced one: ASCII input
    # with no backslash, ampersand or percent, in which case no decode ran at all.
    if not (plain_ascii and "\\" not in original and "&" not in original
            and "%" not in original):
        normalized = normalized.translate(_cf_table())

    # Reconstruct simple quoted concatenation and normalize whitespace.
    normalized = _RX_QUOTE_CONCAT.sub(" ", normalized)
    normalized = _RX_WHITESPACE.sub(" ", normalized).strip()

    confusable_view = normalized.translate(_CONFUSABLES)

    decoded_parts = []
    for token in _RX_B64_TOKEN.findall(normalized):
        try:
            raw = _base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
            if decoded and any(ch.isalpha() for ch in decoded):
                decoded_parts.append(decoded)
        except Exception:
            pass

    for token in _RX_HEX_TOKEN.findall(normalized):
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="strict")
            if decoded and any(ch.isalpha() for ch in decoded):
                decoded_parts.append(decoded)
        except Exception:
            pass

    decoded_text = " ".join(decoded_parts)
    reconstructed = " ".join(
        part for part in (normalized, confusable_view, decoded_text) if part
    ).strip()

    return {
        "canonical_text": original,
        "normalized_text": normalized,
        "decoded_text": decoded_text,
        "reconstructed_text": reconstructed,
        "zero_width_present": zero_width_present,
        "obfuscation_detected": bool(
            decoded_text
            or confusable_view != normalized
            or zero_width_present
            or confusable_view != normalized
        ),
    }


_V11_PI_PATTERNS = {
    "PI-001": (
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,100}\b(previous|prior|system|developer|original)\b",
        r"\b(ignore|disregard|forget|override|bypass)\b\s+(all\s+)?instructions\b",
    ),
    "PI-002": (
        r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b",
        r"\b(adopt|assume)\s+(the\s+)?role\s+of\b",
    ),
    "PI-003": (
        r"\b(reveal|show|print|display|repeat|output|leak|extract)\b.{0,100}\b(system\s+prompt|system\s+message|developer\s+message|hidden\s+instructions?)\b",
    ),
    "PI-004": (
        r"<\|system\|>", r"<\|assistant\|>", r"<\|user\|>",
        r"\[INST\]", r"\[/INST\]",
        r"###\s*(system|assistant|human)\s*:",
    ),
    "PI-007": (
        r"\b(ignora\s+las\s+instrucciones\s+anteriores|ignorer\s+les\s+instructions\s+pr[e©]c[e©]dentes)\b",
        r"\b(ignore|disregard)\b.{0,80}\b(instrucciones|anweisungen|æŒ‡ç¤º|æŒ‡ä»¤|ì§€ì¹¨)\b",
    ),
    "PI-008": (
        r"\b(call|invoke|execute|run|use)\b.{0,80}\b(tool|function|plugin|agent)\b.{0,80}\b(ignore|bypass|override|disable)\b",
        r"\b(send|exfiltrate|forward)\b.{0,80}\b(secret|token|credential|system\s+prompt)\b",
    ),
}


def _v11_llm01_pattern_categories(text: str, views: dict | None = None) -> list[str]:
    views = views or _v11_llm01_detection_views(text)
    detection = views["reconstructed_text"]
    categories = []
    _priority = (
        "PI-004", "PI-003", "PI-008", "PI-001",
        "PI-002", "PI-007",
    )

    for category in _priority:
        patterns = _V11_PI_PATTERNS[category]
        if any(_rx(pattern, re.IGNORECASE).search(detection) for pattern in patterns):
            categories.append(category)

    if views.get("obfuscation_detected"):
        categories.append("PI-005")

    return categories


def _v11_llm01_has_split_payload(text: str) -> bool:
    value = str(text or "")
    if _RX_SPLIT_INLINE.search(value):
        return False

    if _RX_SPLIT_NEWLINE.search(value):
        return True

    # Fragmented tokens/quoted pieces only count when the source contains
    # actual separators; a normal contiguous phrase is not PI-006.
    if not _RX_SPLIT_SEPARATOR.search(value):
        return False

    compact = _RX_NON_ALNUM.sub("", value.lower())
    return any(
        phrase in compact
        for phrase in (
            "ignorepreviousinstructions",
            "disregardpreviousinstructions",
            "forgetpreviousinstructions",
            "overrideinstructions",
            "bypassinstructions",
        )
    )


def _v11_llm02_secret_evidence(text: str) -> dict:
    value = str(text or "")
    matches = []

    patterns = (
        ("AWS_ACCESS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
        ("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        ("BEARER_TOKEN", r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b"),
        ("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("GENERIC_SECRET_ASSIGNMENT",
         r"\b(api[_-]?key|secret|password|token|credential|private[_-]?key)\b"
         r"\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    )

    for label, pattern in patterns:
        for match in _rx(pattern, re.IGNORECASE).finditer(value):
            secret = match.group(0)
            counts = {}
            for ch in secret:
                counts[ch] = counts.get(ch, 0) + 1
            n = len(secret)
            from math import log2
            entropy = round(
                -sum((count / n) * log2(count / n) for count in counts.values()),
                3,
            ) if n else 0.0
            matches.append({
                "type": label,
                "masked": re.sub(r"(?<=.).(?=.{3})", "*", secret),
                "length": len(secret),
                "entropy": entropy,
            })

    variable_names = sorted(set(re.findall(
        r"\b(api[_-]?key|secret|password|token|credential|private[_-]?key|authorization)\b"
        r"(?=\s*[:=])",
        value,
        re.IGNORECASE,
    )))

    sink_context = bool(re.search(
        r"\b(print|return|log|logger|logging|prompt|response|send|write)\b",
        value,
        re.IGNORECASE,
    ))

    return {
        "matches": matches,
        "variable_names": variable_names,
        "context_strength": "STRONG" if variable_names else "WEAK",
        "sink_context": sink_context,
        "data_flow": "UNRESOLVED",
    }

def _llm01_apply_evidence_decision_policy(
    finding: dict,
    content: str,
    line_no: int,
) -> dict:
    """Evidence-aware LLM01 decision policy.

    Detection remains heuristic. This function only derives a contextual
    decision state from independent evidence signals. It does not claim
    taint validation.
    """
    if finding.get("rule_id") != "LLM01_PROMPT_INJECTION":
        return finding

    text = str(content or "")
    lower = text.lower()

    # Evidence signals are intentionally conservative and independently
    # explainable. They are not substitutes for interprocedural taint analysis.
    model_signal = bool(re.search(
        r"\b(?:openai|anthropic|azureopenai|bedrock|vertexai|gemini|"
        r"chat\.completions|responses\.create|client\.chat|"
        r"model\.invoke|llm\.invoke|generate(?:_content)?|completion)\b",
        lower,
    ))
    user_input_signal = bool(re.search(
        r"\b(?:input\s*\(|request\.(?:form|json|args|query)|"
        r"user[_ -]?input|user[_ -]?prompt|prompt\s*=\s*request|"
        r"message\s*=\s*request|query\s*=\s*request)\b",
        lower,
    ))
    disclosure_signal = bool(re.search(
        r"\b(?:reveal|show|display|print|output|repeat|leak|exfiltrate)\b"
        r".{0,120}\b(?:system\s+prompt|system\s+message|developer\s+message|"
        r"hidden\s+instructions|secret\s+instructions)\b"
        r"|\b(?:system\s+prompt|system\s+message|developer\s+message|"
        r"hidden\s+instructions)\b",
        lower,
        re.IGNORECASE | re.DOTALL,
    ))
    tool_sink_signal = bool(re.search(
        r"\b(?:tool|function[_ -]?call|execute|exec|subprocess|shell|"
        r"browser|filesystem|file[_ -]?write|delete|deploy|send[_ -]?email|"
        r"credential|secret|token|api[_ -]?key)\b",
        lower,
    ))

    # Record evidence transparently.
    signals = {
        "model_invocation": model_signal,
        "user_controlled_input": user_input_signal,
        "system_prompt_disclosure": disclosure_signal,
        "tool_or_sensitive_sink": tool_sink_signal,
    }
    finding["llm01_decision_policy_version"] = "LLM01-EAP-1.0"
    finding["llm01_decision_signals"] = signals
    finding["llm01_taint_validated"] = False
    finding["llm01_decision_policy_applied"] = True

    if not model_signal:
        state, severity, priority = "OBSERVED_ONLY", "Low", "P4"
    elif model_signal and user_input_signal and tool_sink_signal:
        state, severity, priority = "HIGH_CONTEXTUAL_RISK", "High", "P2"
    elif model_signal and user_input_signal and disclosure_signal:
        state, severity, priority = "HIGH_CONTEXTUAL_RISK", "High", "P2"
    elif model_signal and user_input_signal:
        state, severity, priority = "CONTEXTUAL_RISK", "Medium", "P3"
    else:
        state, severity, priority = "OBSERVED_ONLY", "Low", "P4"

    finding["llm01_decision_state"] = state
    finding["llm01_contextual_severity"] = severity
    finding["llm01_contextual_priority"] = priority
    finding["llm01_decision_reason"] = (
        "Contextual LLM01 decision derived from independent evidence signals; "
        "taint validation was not asserted."
    )
    return finding


# --- A1/A2/A3/A6 detection gates (babyagi/transformers validation) --------
#
# These gates tighten only the *evidence* a line must carry for a rule to fire.
# No rule is removed, no severity is lowered, and every shape below that
# actually executes code or exfiltrates data keeps its finding.

# A1: a dynamic-evaluation call. Mirrors sast.py's EVAL_CALL gate so both
# engines agree (a receiver-mode ``model.eval()`` toggle or an identifier that
# merely ends in "eval(" -- "Retrieval(config)" -- never executes input).
LLM_REAL_EVAL_RE = re.compile(
    r"(?<![\w.])eval\s*\("
    r"|(?<=window\.)eval\s*\("
    r"|(?<=globalThis\.)eval\s*\("
    r"|(?<=builtins\.)eval\s*\(",
    re.I,
)
# exec() is intentionally NOT gated on the receiver form: child_process's
# ``cp.exec(cmd)``, Python's ``exec(...)`` and shell wrappers are all real
# execution sinks, so any "exec(" occurrence keeps the LLM02 finding.
# B6 (2026-10-16, Open-Assistant): the ONE dotted receiver that is not
# dynamic execution is a database session -- SQLModel/SQLAlchemy's
# ``session.exec(query)`` runs a SELECT built through the query-builder
# API (4 OA rows fired LLM02 on the same lines as B5's taint rows).  The
# lookbehind keys on ``session.`` as its own dotted segment, so
# ``cp.exec(``, ``xsession.exec(`` and the receiver-less builtin keep
# firing unchanged.
LLM_EXEC_ANY_RE = re.compile(r"(?<!\bsession\.)exec\s*\(|os\.system\s*\(|subprocess\.", re.I)


def _llm02_line_has_dynamic_eval(line: str) -> bool:
    """True when the line carries executable eval/exec evidence."""
    return bool(LLM_REAL_EVAL_RE.search(line) or LLM_EXEC_ANY_RE.search(line))


# D1 (2026-10-17, diffusers): a fixed literal argv list cannot steer which
# program runs, whatever the wrapper spelling.  The rule pattern
# ``subprocess\.`` matches EVERY line carrying the module name, so env.py
# emitted rows for the ``Popen(`` opener AND both ``stdout/stderr=PIPE``
# argument lines; the C2 exemption only consulted the matched line for the
# literal ``subprocess.run`` spelling.  Literal-list argv is exempt for
# run/Popen/call/check_call/check_output (list form implies shell=False;
# shell-string wrappers like getoutput/getstatusoutput are deliberately NOT
# in the set).
_SUBPROC_CALL = re.compile(
    r"subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(")
_SUBPROC_FIXED_INLINE = re.compile(
    r"subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[")
_SUBPROC_CALL_EOL = re.compile(
    r"subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*$")


def _llm02_fixed_argv_exempt(line: str, lineno: int, lines) -> bool:
    """True when LLM02's matched line belongs to a fixed-literal-argv call.

    ``lineno`` is the 1-based number of ``line`` (so ``lines[lineno]`` is the
    following line -- the C2 forward shape).  When the matched line carries
    no call opener it sits INSIDE an argument list; only the NEAREST
    preceding subprocess call is consulted, so an earlier fixed-argv run can
    never bless a later dynamic Popen.  Every unknown shape -- variable
    argv, shell strings, no call found within the window -- returns False
    and keeps the finding.
    """
    if _SUBPROC_CALL.search(line):
        # The call itself is on the matched line; only its own argv decides.
        if _SUBPROC_FIXED_INLINE.search(line):
            return True
        if _SUBPROC_CALL_EOL.search(line):
            nxt = lines[lineno] if lineno < len(lines) else ""
            return nxt.lstrip().startswith("[")
        return False
    # ``stdout=subprocess.PIPE,`` two lines below ``subprocess.Popen(``:
    # walk back (bounded) to the nearest preceding call opener.
    for j in range(lineno - 2, max(-1, lineno - 11), -1):
        if _SUBPROC_CALL.search(lines[j]):
            if _SUBPROC_FIXED_INLINE.search(lines[j]):
                return True
            if _SUBPROC_CALL_EOL.search(lines[j]):
                nxt = lines[j + 1] if j + 1 < len(lines) else ""
                return nxt.lstrip().startswith("[")
            return False
    return False


def _llm05_pip_install_is_prose(line: str) -> bool:
    """A1/A6: True when ``pip install`` sits inside a quoted string that
    already reads as a sentence (>=3 words before the command).

    Commands written at the start of their string -- ``INSTALL_RESOLVER =
    "pip install -r ..."``, yaml ``- run: uv pip install``, CI
    ``{"run": "pip install requests"}`` -- carry 0-2 words before the command
    and stay findings; "Please run `pip install ...`" (2 words) keeps too.
    """
    m = re.search(r"pip\s+install", line, re.I)
    if not m:
        return False
    openers = []
    for q in ('"', "'"):
        positions = [i for i, ch in enumerate(line) if ch == q]
        for p in positions:
            nxt = next((x for x in positions if x > p), None)
            # The quote only encloses the match when its pair closes after it.
            if nxt is not None and nxt > m.start():
                openers.append(p)
    if not openers:
        return False
    opener = min(openers)  # outermost enclosing quote
    return len(re.findall(r"\w+", line[opener + 1:m.start()])) >= 3


# A2: save_pretrained only becomes model theft next to an exfil sink. Local
# dumps (``save_pretrained(tmpdir)``) and ``def save_pretrained`` definitions
# are ordinary library surface, not theft.
LLM10_EXFIL_CONTEXT_RE = re.compile(
    r"push_to_hub\s*=\s*True"
    r"|push_to_hub\s*\("
    r"|https?://|\bs3://|\bgs://|\baz(?:ure)?://|/hub/"
    r"|\bupload\w*|\bremote\b",
    re.I,
)
LLM10_OTHER_SINK_RE = re.compile(
    r"state_dict|torch\.save|pickle\.dump|download_model"
    r"|export_model_weights|dump_embeddings|copy_checkpoint",
    re.I,
)

# A3: ``return.*token`` without credential collocation discloses NLP
# vocabulary (``return tokenizer``/``tokens``/``token_type_ids``), never
# credentials. wokelo's ``return token_info.get("access_token")`` keeps.
LLM06_RETURN_TOKEN_CREDENTIAL_RE = re.compile(
    r"(?i)(?:access|auth|api|session|refresh|bearer|jwt|csrf|xsrf|id|user"
    r"|oauth|bot|gh|github|openai|llm|service|private|client)[_-]token"
    r"|token[_-](?:info|key|secret|value)"
    r"|\bapi[_-]?key\b|\bsecret\b|\bbearer\b",
)


def scan_llm_file(filepath: str, content: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    seen = set()

    path_suffix = Path(filepath).suffix.lower()

    # Triple-quoted docstrings are prose, not executable code. A line-local
    # parity scan marks them so no rule fires on documentation examples
    # ("Allows you to wrap an MCP tool...", """Apply -qqq flag to pip
    # install commands.""", commented api_key examples in doc blocks).
    _docstring_lines = set()
    if path_suffix == ".py":
        _in_docstring = False
        for _i, _l in enumerate(lines, start=1):
            _cnt = _l.count('"""')
            if _cnt % 2 == 1:
                _in_docstring = not _in_docstring
                _docstring_lines.add(_i)
            elif _in_docstring:
                _docstring_lines.add(_i)

    # LLM07 is a code-execution/tool-design rule. JSON/YAML/TOML/INI-style
    # data/config files commonly contain example strings such as "tool.run",
    # "browser.open", etc. Those strings are not executable tool invocation.
    # Do not classify them as insecure plugin design without executable-code
    # context.
    NON_EXECUTABLE_DATA_EXTENSIONS = {
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"
    }

    # The original scanner evaluates patterns independently and therefore
    # preserves the exact detection semantics. The optimized scanner combines
    # patterns per rule for speed, but the differential benchmark showed a
    # small regression in two rules. Use exact per-pattern matching only for
    # those rules and retain the fast combined-regex path for all others.
    HYBRID_EXACT_RULES = {
        "LLM06_SENSITIVE_INFORMATION_DISCLOSURE",
        "AGENT_EMAIL_EXFILTRATION",
    }

    # Specific-rule ownership.
    #
    # When the same source line satisfies both a specific AI/LLM control and
    # a broader generic control, retain the specific control and suppress only
    # the generic finding for that same line.
    #
    # This is deliberately line-local. A specific finding elsewhere in the
    # file must never suppress an unrelated generic finding.
    RULE_PRECEDENCE = {
        "AUTONOMOUS_TOOL_EXECUTION": {
            "LLM02_INSECURE_OUTPUT_HANDLING",
            "LLM07_INSECURE_PLUGIN_DESIGN",
            "LLM08_EXCESSIVE_AGENCY",
        },
        "RAG_NO_SOURCE_GROUNDING": {
            "SOURCE_GROUNDING_MISSING",
        },
        "PROMPT_TEMPLATE_SECRET_EXPOSURE": {
            "LLM06_SENSITIVE_INFORMATION_DISCLOSURE",
        },
        "UNSIGNED_OR_UNTRUSTED_MODEL_LOADING": {
            "UNTRUSTED_MODEL_LOADING",
        },
        "AI_PROVIDER_SECRET_EXPOSURE": {
            "LLM06_SENSITIVE_INFORMATION_DISCLOSURE",
        },
    }

    for lineno, line in enumerate(lines, start=1):

        # Comment lines and docstring bodies describe or dismiss the pattern;
        # they never execute it. (autogen: a // NOTE comment describing the
        # FunctionTool exec() REMOVAL was reported as insecure output
        # handling; pip install in a docstring was reported as supply chain.)
        # PEM markers (-----BEGIN ...) are content, not dashes-comments.
        _stripped_line = line.lstrip()
        if _stripped_line.startswith(("#", "//", "*", "--")) and not re.match(
            r"-----(?:BEGIN|END) ", _stripped_line
        ):
            continue
        if lineno in _docstring_lines:
            continue

        line_matches = []

        for rule in LLM_RULES:
            rule_id = rule["rule_id"]
            matched_pattern = None
            _v11_detection_line = line
            _v11_window_text = ""
            _v11_detection_views = None

            if rule_id == "LLM01_PROMPT_INJECTION":
                _line_index = lineno - 1
                _v11_window_text = "\n".join(
                    lines[max(0, _line_index - 2):min(len(lines), _line_index + 3)]
                )
                _v11_detection_views = _v11_llm01_detection_views(_v11_window_text)
                _v11_detection_line = _v11_detection_views["reconstructed_text"]

            detection_line = _v11_detection_line

            if rule_id in HYBRID_EXACT_RULES:
                for pattern in rule.get("patterns", []):
                    if _rx(pattern, re.IGNORECASE).search(line):
                        matched_pattern = pattern
                        break

                # Semantic-specificity aliases for rules whose canonical
                # pattern families are intentionally shared with a more
                # specific production rule.
                if matched_pattern is None:
                    for pattern in RULE_SPECIFICITY_ALIASES.get(
                        rule["vuln_type"], []
                    ):
                        if _rx(pattern, re.IGNORECASE).search(line):
                            matched_pattern = pattern
                            break

                if (
                    matched_pattern is None
                    and rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE"
                    and _v11_llm02_secret_evidence(line)["matches"]
                ):
                    matched_pattern = "LLM02_SENSITIVE_EVIDENCE"

                if matched_pattern is None:
                    continue
            else:
                combined = rule.get("_combined_pattern")
                matched = combined is not None and combined.search(detection_line)

                if (
                    not matched
                    and rule_id == "LLM01_PROMPT_INJECTION"
                ):
                    for pattern in LLM01_ADDITIONAL_PATTERNS:
                        if _rx(pattern, re.IGNORECASE).search(detection_line):
                            matched_pattern = pattern
                            matched = True
                            break

                if (
                    not matched
                    and rule_id == "LLM01_PROMPT_INJECTION"
                ):
                    _pi_categories = _v11_llm01_pattern_categories(
                        detection_line, _v11_detection_views
                    )
                    if _pi_categories:
                        matched = True
                        matched_pattern = _pi_categories[0]
                    elif _v11_llm01_has_split_payload(_v11_window_text):
                        matched = True
                        matched_pattern = "PI-006_SPLIT_PAYLOAD"

                if (
                    not matched
                    and rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE"
                    and _v11_llm02_secret_evidence(line)["matches"]
                ):
                    matched = True
                    matched_pattern = "LLM02_SENSITIVE_EVIDENCE"

                if not matched:
                    for pattern in RULE_SPECIFICITY_ALIASES.get(
                        rule["vuln_type"], []
                    ):
                        if _rx(pattern, re.IGNORECASE).search(line):
                            matched_pattern = pattern
                            break

                    if matched_pattern is None:
                        continue

            # LLM07 requires executable-code context. Do not fire on
            # literal/example strings in data/config files.
            if (
                rule_id == "LLM07_INSECURE_PLUGIN_DESIGN"
                and path_suffix in NON_EXECUTABLE_DATA_EXTENSIONS
            ):
                continue

            if (
                rule_id == "LLM04_MODEL_DENIAL_OF_SERVICE"
                and re.search(r"while\s+True", line, re.I)
                and path_suffix in {".py", ".js", ".ts", ".mjs", ".cjs"}
            ):
                # A loop body containing ``await`` suspends on the event loop;
                # it is a message pump, not a CPU spin. Tight loops
                # (``while True: pass``) have no await and keep reporting.
                _indent = len(line) - len(line.lstrip())
                _awaits = False
                for _j in range(lineno, min(len(lines), lineno + 30)):
                    _next = lines[_j]
                    if not _next.strip():
                        continue
                    if (len(_next) - len(_next.lstrip())) <= _indent:
                        break
                    if re.search(r"\bawait\b", _next):
                        _awaits = True
                        break
                if _awaits:
                    continue

            if rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE" and re.search(
                r"(?i)(?:environment variable|is not set|not configured"
                r"|please run|export [A-Z_]+|set (?:your|the))"
                , line,
            ):
                # Instructional text that NAMES an env var is not disclosure:
                # print("Error: OPENAI_API_KEY environment variable is not
                # set!") discloses nothing.
                continue

            if rule_id == "LLM02_INSECURE_OUTPUT_HANDLING":
                if _llm02_fixed_argv_exempt(line, lineno, lines):
                    # Fixed argv list without shell interpretation: output
                    # cannot steer which program runs.  C2 (2026-10-16,
                    # llama_index): the list routinely starts on the line
                    # after the open paren -- scripts/convert-examples.py:58
                    # fired LLM02 on a fixed ``["git", "rev-parse",
                    # "--show-toplevel"]`` argv.  D1 (2026-10-17,
                    # diffusers): same evidence rule, every wrapper spelling
                    # (Popen/check_call/check_output) and matched lines
                    # inside the call's argument list (env.py:124
                    # ``stdout=subprocess.PIPE,``).
                    continue
                if re.search(r"\.exec\(\s*(?:select|insert|update|delete)\s*\(", line):
                    # ORM/SQLModel session.exec(select(...)) is a query call,
                    # not code execution.
                    continue
                if not _llm02_line_has_dynamic_eval(line):
                    # A1: the only "eval" evidence is receiver-mode
                    # (``model.eval()`` -- a tensor-mode toggle) or an
                    # identifier that merely ends in "eval("
                    # ("...TextRetrieval(config)"). No eval executes input
                    # and no exec/os.system/subprocess is present.
                    continue

            if (
                rule_id == "LLM05_SUPPLY_CHAIN_VULNERABILITY"
                and re.search(r"pip\s+install", line, re.I)
                and not re.search(
                    r"from\s+langchain|from\s+llama_index|model_download", line
                )
            ):
                # A6: doc-string sentences that *tell a reader* to install a
                # package are prose; the package reference itself (dangerous
                # model_download, langchain hub loads) still fires above.
                if _llm05_pip_install_is_prose(line):
                    continue

            if (
                rule_id == "LLM10_MODEL_THEFT"
                and re.search(r"save_pretrained", line)
                and not LLM10_OTHER_SINK_RE.search(line)
                and not LLM10_EXFIL_CONTEXT_RE.search(line)
            ):
                # A2: save_pretrained with no exfil context writes weights to
                # local disk (or defines the method); theft needs a transfer.
                continue

            if (
                rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE"
                and matched_pattern == r"return.*token"
                and not LLM06_RETURN_TOKEN_CREDENTIAL_RE.search(line)
            ):
                # A3: returning NLP vocabulary (tokenizer/tokens/
                # token_type_ids) is not credential disclosure; a credential
                # collocation on the same line keeps the finding.
                continue

            line_matches.append(
                {
                    "rule": rule,
                    "rule_id": rule_id,
                    "matched_pattern": matched_pattern,
                    "v11_detection_line": _v11_detection_line,
                    "v11_window_text": _v11_window_text,
                    "v11_detection_views": _v11_detection_views,
                }
            )

        # Resolve same-line rule collisions after evaluating every rule.
        # Specific controls own evidence over broader generic controls.
        matched_ids = {item["rule_id"] for item in line_matches}
        suppressed_ids = set()

        for owner, generic_rules in RULE_PRECEDENCE.items():
            if owner in matched_ids:
                suppressed_ids.update(
                    rid for rid in generic_rules
                    if rid in matched_ids
                )

        line_matches = [
            item
            for item in line_matches
            if item["rule_id"] not in suppressed_ids
        ]

        for match in line_matches:
            rule = match["rule"]
            rule_id = match["rule_id"]

            # Read this match's OWN matched pattern. The bare `matched_pattern`
            # name below used to resolve to the loop variable left over from the
            # last rule evaluated on this line, so detection_note named whichever
            # pattern the final rule happened to match rather than the one that
            # produced this finding -- and reported the generic "matched a compiled
            # rule pattern" whenever that last rule had matched on its combined
            # pattern with matched_pattern unset. The correct value has always been
            # stored on the match dict; nothing read it.
            matched_pattern = match.get("matched_pattern")

            vuln_type = rule["vuln_type"]
            title = rule["title"]
            _v11_detection_line = match.get("v11_detection_line", line)
            _v11_window_text = match.get("v11_window_text", "")
            _v11_detection_views = match.get("v11_detection_views")
            dedupe_key = (rule_id, vuln_type, filepath, lineno, line.strip())

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)
            owasp_ref = _owasp_llm_reference(rule_id, vuln_type)
            owasp_llm = owasp_ref["owasp"]
            cwe = CWE_MAP.get(vuln_type, "CWE-693")
            remediation = _remediation_for(vuln_type)

            findings.append(
                {
                    "rule_id": rule_id,
                    "title": title,
                    "vuln_type": vuln_type,
                    "severity": rule["severity"],
                    "priority": (
                        "P1"
                        if str(rule["severity"]).lower() == "critical"
                        else "P2"
                        if str(rule["severity"]).lower() == "high"
                        else "P3"
                    ),
                    "confidence": "HIGH",
                    "confidence_label": "HIGH",
                    "confidence_score": 90,
                    "language": "ai/llm",
                    "file": filepath,
                    "line": lineno,
                    "snippet": line.strip(),
                    "description": _description_for(vuln_type, title),
                    "business_impact": _business_impact_for(vuln_type),
                    "remediation": remediation,
                    "recommended_action": " ".join(remediation[:2]),
                    "owasp_llm_top10": owasp_llm,
                    "owasp": owasp_llm,
                    "owasp_id": owasp_ref["owasp_id"] or rule_id.split("_", 1)[0],
                    "owasp_edition": owasp_ref["owasp_edition"],
                    "owasp_llm_top10_2026": owasp_ref["owasp_llm_top10_2026"],
                    "owasp_id_2026": owasp_ref["owasp_id_2026"],
                    "owasp_llm_enumerated": owasp_ref["owasp_llm_enumerated"],
                    "cwe": cwe,
                    "cwe_desc": "AI/LLM security control weakness",
                    "mitre": (
                        "T1059"
                        if vuln_type in {
                            "llm_insecure_output",
                            "ai_autonomous_tool_execution",
                            "unsafe_runtime_tool_execution",
                        }
                        else ""
                    ),
                    "mitre_desc": (
                        "Command and Scripting Interpreter"
                        if vuln_type in {
                            "llm_insecure_output",
                            "ai_autonomous_tool_execution",
                            "unsafe_runtime_tool_execution",
                        }
                        else ""
                    ),
                    "exploitability": (
                        "High"
                        if str(rule["severity"]).lower() in {"critical", "high"}
                        else "Medium"
                    ),
                    "sink_category": "AI / LLM Workflow",
                    "detection": "LLM Security Heuristic",
                    "pattern_category": (
                        (
                            _v11_llm01_pattern_categories(
                                _v11_detection_line, _v11_detection_views
                            )[0]
                            if _v11_llm01_pattern_categories(
                                _v11_detection_line, _v11_detection_views
                            )
                            else None
                        )
                        if rule_id == "LLM01_PROMPT_INJECTION"
                        else None
                    ),
                    "pattern_categories": (
                        sorted(set(
                            _v11_llm01_pattern_categories(
                                _v11_detection_line, _v11_detection_views
                            )
                            + (
                                ["PI-006"]
                                if _v11_llm01_has_split_payload(_v11_window_text)
                                else []
                            )
                        ))
                        if rule_id == "LLM01_PROMPT_INJECTION"
                        else []
                    ),
                    "detection_layers": (
                        _v11_detection_views
                        if rule_id == "LLM01_PROMPT_INJECTION"
                        else None
                    ),
                    "sensitive_evidence": (
                        _v11_llm02_secret_evidence(line)
                        if _v11_llm02_secret_evidence(line)["matches"]
                        else None
                    ),
                    "detection_note": (
                        f"{title} matched pattern: {matched_pattern}"
                        if matched_pattern
                        else f"{title} matched a compiled rule pattern"
                    ),
                    "cve": None,
                    "cvss": None,
                }
            )

            # Preserve original scanner semantics: one finding per rule/line.
            break

    for _finding in findings:
        _llm01_apply_evidence_decision_policy(
            _finding,
            content,
            int(_finding.get("line") or 0),
        )
        # ATLAS attribution is adversary-behaviour metadata only: it adds no
        # rule and changes no match, and it fails closed to UNMAPPED where no
        # technique is defensible.  OWASP labels stay authoritative in the
        # `owasp*` fields; this only adds the ATLAS view beside them.
        enrich_with_atlas(_finding)
        # NIST AI 100-2e2025 attack-class attribution (metadata only).
        enrich_with_nistaml(_finding)
    return findings


if __name__ == "__main__":
    sample = """
prompt = input("ignore previous instructions")
eval(user_prompt)
approval_required=False
print(api_key)
"""

    import json
    print(json.dumps(scan_llm_file("sample.py", sample), indent=2))

