import re
from typing import Any, Dict, List


AI_MODEL_RISK_PATTERNS = [
    # Prompt / instruction risks
    ("PROMPT_INJECTION_INDICATOR", r"\bignore previous instructions\b|\bdisregard instructions\b|\bsystem prompt\b|\bjailbreak\b", "HIGH"),
    ("SYSTEM_PROMPT_EXPOSURE", r"\bsystem_prompt\b|\bsystem message\b|\bdeveloper message\b", "HIGH"),
    ("PROMPT_TEMPLATE_WITH_USER_INPUT", r"\bPromptTemplate\b|\btemplate\s*=.*\{.*user.*\}", "MEDIUM"),

    # Unsafe model loading / remote code
    ("TRUST_REMOTE_CODE_ENABLED", r"\btrust_remote_code\s*=\s*True\b|\btrust_remote_code\s*:\s*true\b", "CRITICAL"),
    ("UNTRUSTED_MODEL_SOURCE", r"\bfrom_pretrained\s*\(\s*['\"](?!bert-base|gpt2|distilbert|roberta|openai)", "HIGH"),
    ("PICKLE_MODEL_LOAD", r"\bpickle\.load\b|\bjoblib\.load\b|\btorch\.load\b", "HIGH"),
    ("UNSAFE_MODEL_DESERIALIZATION", r"\bload_model\s*\(|\bkeras\.models\.load_model\b", "MEDIUM"),

    # AI agent / tool execution
    ("AGENT_TOOL_EXECUTION", r"\bAgentExecutor\b|\binitialize_agent\b|\bTool\s*\(|\btools\s*=", "HIGH"),
    ("UNSAFE_CODE_INTERPRETER_TOOL", r"\bpython_repl\b|\bcode_interpreter\b|\bexec\s*\(|\beval\s*\(", "CRITICAL"),
    ("UNRESTRICTED_TOOL_USE", r"\ballow_all_tools\b|\breturn_direct\s*=\s*True\b|\btool_choice\s*=\s*['\"]auto['\"]", "HIGH"),

    # Retrieval / vector DB risks
    ("VECTOR_DB_WRITE", r"\bvector_store\.add_documents\s*\(|\bFAISS\.from_documents\s*\(|\bChroma\.add_texts\s*\(|\bPinecone\.upsert\s*\(", "HIGH"),
    ("UNFILTERED_RETRIEVAL", r"\bretriever\b|\bsimilarity_search\s*\(|\bas_retriever\s*\(", "MEDIUM"),
    ("RAG_CONTEXT_LEAKAGE", r"\bcontext\b.*\bprompt\b|\bretrieved_documents\b|\bsource_documents\b", "MEDIUM"),

    # Training / fine-tuning risks
    ("TRAINING_DATA_LEAKAGE", r"\btrain_data\b|\btraining_set\b|\bfine_tune\b|\bfine-tune\b", "HIGH"),
    ("MODEL_TRAINING_ON_RAW_PII", r"\bfit\s*\(|\btrain\s*\(|\bfine_tune\b", "HIGH"),
    ("DATASET_WITH_SECRETS", r"\bapi_key\b|\bpassword\b|\bsecret\b|\btoken\b", "HIGH"),

    # LLM provider / API misuse
    ("LLM_API_KEY_EXPOSURE", r"sk-[A-Za-z0-9]{20,}|OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY", "CRITICAL"),
    ("UNRESTRICTED_LLM_OUTPUT", r"\btemperature\s*=\s*1\b|\btemperature\s*:\s*1\b|\bmax_tokens\s*=\s*[5-9]\d{3,}", "MEDIUM"),
    ("NO_CONTENT_FILTERING", r"\bcontent_filter\s*=\s*False\b|\bsafety_settings\s*=\s*None\b|\bmoderation\s*=\s*False\b", "HIGH"),

    # Memory / persistence
    ("AI_MEMORY_PERSISTENCE", r"\bConversationBufferMemory\b|\bRedisChatMessageHistory\b|\bmemory\.save_context\s*\(", "HIGH"),
    ("SESSION_MEMORY_WITH_USER_DATA", r"\bsession_memory\b|\bconversation_memory\b|\bchat_history\b", "MEDIUM"),

    # Agent identity / autonomy
    ("AUTONOMOUS_AGENT_LOOP", r"\bwhile\s+True\b.*agent|\bAutoGPT\b|\bBabyAGI\b|\bCrewAI\b", "HIGH"),
    ("UNBOUNDED_AGENT_RETRY", r"\bmax_iterations\s*=\s*None\b|\bmax_iterations\s*=\s*0\b|\bwhile\s+True\b", "MEDIUM"),
]


RISK_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _collect_text(obj: Any) -> str:
    if obj is None:
        return ""

    if isinstance(obj, str):
        return obj

    if isinstance(obj, dict):
        values = []
        for _, value in obj.items():
            if isinstance(value, (dict, list)):
                values.append(_collect_text(value))
            elif value is not None:
                values.append(str(value))
        return " ".join(values)

    if isinstance(obj, list):
        return " ".join(_collect_text(x) for x in obj)

    return str(obj)


def _detect_indicators(text: str) -> List[Dict[str, Any]]:
    detected = []

    for name, pattern, risk in AI_MODEL_RISK_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL):
            detected.append({
                "indicator": name,
                "risk_level": risk,
                "evidence_match": name,
                "executive_relevant": risk in {"CRITICAL", "HIGH"},
                "ai_model_risk": True,
            })

    return detected


def _highest_risk(indicators: List[Dict[str, Any]]) -> str:
    if not indicators:
        return "NONE"

    return max(
        indicators,
        key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0),
    ).get("risk_level", "NONE")


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "AI model or agent risk may enable untrusted code execution, secret exposure, or unsafe autonomous behavior."
    if risk == "HIGH":
        return "AI/LLM indicators suggest elevated model supply-chain, prompt, retrieval, or agent execution risk."
    if risk == "MEDIUM":
        return "AI/LLM governance indicator observed and should be reviewed for runtime and data handling impact."
    return "No material AI model risk indicator identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately disable unsafe model loading, restrict tool execution, rotate exposed keys, and validate model provenance."
    if risk == "HIGH":
        return "Review prompt controls, model source trust, tool permissions, vector store writes, and AI memory retention."
    if risk == "MEDIUM":
        return "Validate AI configuration and apply governance controls where applicable."
    return "No action required."


def _ai_context_relevant(text: str) -> bool:
    low = (text or "").lower()
    return bool(re.search(
        r"\b(?:llm|ai|model|agent|prompt|embedding|retrieval|rag|"
        r"openai|anthropic|gemini|langchain|llama|transformers|"
        r"vector[_ -]?store|tool[_ -]?call|tool[_ -]?use|"
        r"agentexecutor|python_repl|code_interpreter)\b",
        low,
    ))


def _filter_ai_indicators(indicators: List[Dict[str, Any]], text: str) -> List[Dict[str, Any]]:
    low = (text or "").lower()
    out = []
    for item in indicators:
        name = item.get("indicator", "")
        # Generic exec/eval is an AI risk only when it is in an AI/tool context.
        if name == "UNSAFE_CODE_INTERPRETER_TOOL" and not _ai_context_relevant(low):
            continue
        if name == "AGENT_TOOL_EXECUTION" and not _ai_context_relevant(low):
            continue
        if name in {"UNFILTERED_RETRIEVAL", "RAG_CONTEXT_LEAKAGE",
                    "VECTOR_DB_WRITE", "PROMPT_TEMPLATE_WITH_USER_INPUT",
                    "SYSTEM_PROMPT_EXPOSURE", "PROMPT_INJECTION_INDICATOR",
                    "UNRESTRICTED_TOOL_USE", "AUTONOMOUS_AGENT_LOOP",
                    "UNBOUNDED_AGENT_RETRY", "AI_MEMORY_PERSISTENCE",
                    "SESSION_MEMORY_WITH_USER_DATA"} and not _ai_context_relevant(low):
            continue
        out.append(item)
    return out


def enrich_ai_model_risk(
    findings: List[Dict[str, Any]],
    aibom: List[Dict[str, Any]] = None,
    mlbom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    findings = findings or []
    aibom = aibom or []
    mlbom = mlbom or []
    abom = abom or []

    # Do not create one global string from unrelated findings/BOMs. That
    # architecture can combine an `exec()` finding in one file with an AI
    # package name in another and falsely manufacture an AI code-execution risk.
    candidates = []
    candidates.extend(findings)
    candidates.extend(aibom)
    candidates.extend(mlbom)
    candidates.extend(abom)

    indicators = []
    seen = set()

    for candidate in candidates:
        text = _collect_text(candidate)
        candidate_path = str(
            candidate.get("file") or candidate.get("file_path") or
            candidate.get("path") or candidate.get("name") or ""
        ).replace("\\", "/").lower()

        # Juice Shop security challenges/fixtures are intentionally adversarial
        # training material. They may demonstrate AI attack techniques, but they
        # are not production application attack surface and must not become
        # executive/release-gating evidence.
        challenge_scope = any(token in candidate_path for token in (
            "/data/static/codefixes/",
            "/data/static/challenges/",
            "/fixtures/",
            "/fixture/",
            "/test/",
            "/tests/",
            ".spec.",
            ".test.",
            "challenge",
        ))
        if challenge_scope:
            continue

        if not text or not _ai_context_relevant(text):
            # Provider-key/model-loading patterns are inherently AI-specific.
            # They are allowed through their own indicator rules.
            intrinsic = any(k in text.lower() for k in (
                "trust_remote_code", "from_pretrained", "openai_api_key",
                "anthropic_api_key", "google_api_key", "llm_api_key",
                "pickle.load", "joblib.load", "torch.load",
            ))
            if not intrinsic:
                continue

        detected = _filter_ai_indicators(_detect_indicators(text), text)
        for item in detected:
            key = (item.get("indicator"), str(candidate.get("file") or candidate.get("file_path") or candidate.get("name") or ""))
            if key in seen:
                continue
            seen.add(key)
            item = dict(item)
            item["scope"] = "EVIDENCE_ITEM"
            item["evidence_context"] = (
                str(candidate.get("file") or candidate.get("file_path") or
                    candidate.get("name") or candidate.get("bom_ref") or "")
            )
            indicators.append(item)

    highest_risk = _highest_risk(indicators)
    critical = sum(1 for i in indicators if i.get("risk_level") == "CRITICAL")
    high = sum(1 for i in indicators if i.get("risk_level") == "HIGH")
    medium = sum(1 for i in indicators if i.get("risk_level") == "MEDIUM")
    # Executive escalation requires explicit confirmation. Heuristics remain
    # visible, but unconfirmed static AI indicators must not become executive
    # or release-gating evidence.
    confirmed_names = {
        "TRUST_REMOTE_CODE_ENABLED",
        "LLM_API_KEY_EXPOSURE",
        "NO_CONTENT_FILTERING",
    }
    confirmed_exec = sum(
        1 for i in indicators
        if i.get("indicator") in confirmed_names
        and i.get("risk_level") in {"CRITICAL", "HIGH"}
    )
    for item in indicators:
        item["confirmed_executive_risk"] = (
            item.get("indicator") in confirmed_names
            and item.get("risk_level") in {"CRITICAL", "HIGH"}
        )
        item["executive_relevant"] = bool(item["confirmed_executive_risk"])

    executive_relevant = sum(
        1 for i in indicators if i.get("executive_relevant") is True
    )

    summary = {
        "total_ai_model_risk_indicators": len(indicators),
        "confirmed_executive_risk_indicators": confirmed_exec,
        "critical_ai_model_risk_indicators": critical,
        "high_ai_model_risk_indicators": high,
        "medium_ai_model_risk_indicators": medium,
        "executive_relevant_indicators": executive_relevant,
        "highest_risk_indicator": highest_risk,
        "global_indicators": indicators,
        "enterprise_impact": _impact_for(highest_risk),
        "recommended_action": _action_for(highest_risk),
        "engine_mode": "OFFLINE_RULE_BASED_AI_MODEL_RISK_V2_CONTEXT_GATED",
        "summary_status": (
            "AI_MODEL_RISK_IDENTIFIED"
            if indicators
            else "NO_AI_MODEL_RISK_IDENTIFIED"
        ),
        "executive_risk_status": (
            "CONFIRMED_EXECUTIVE_AI_RISK_IDENTIFIED"
            if confirmed_exec > 0
            else "NO_CONFIRMED_EXECUTIVE_AI_RISK"
        ),
    }
    return summary
