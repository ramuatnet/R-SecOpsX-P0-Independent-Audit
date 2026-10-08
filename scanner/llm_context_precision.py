from __future__ import annotations

"""
R-SecOpsX LLM Context Precision Layer

Purpose:
- Preserve every raw LLM scanner finding.
- Reclassify obvious lexical/context false positives.
- Do NOT change the underlying LLM scanner rules.
- Provide raw/actionable/contextual counts for benchmarking.

This module is deliberately conservative: when context is ambiguous,
the finding remains actionable rather than being silently discarded.
"""

import re
from pathlib import Path


LLM_CONTEXT_TERMS = re.compile(
    r"\b("
    r"llm|ai|model|openai|anthropic|gemini|chatgpt|"
    r"prompt|systemprompt|system_prompt|completion|"
    r"chatbot|agent|rag|retrieval|embedding|vector|"
    r"tool.?call|function.?call|inference|"
    r"model.?response|model.?output"
    r")\b",
    re.IGNORECASE,
)

SENSITIVE_TERMS = re.compile(
    r"\b(api[_-]?key|secret|password|token|credential|"
    r"authorization|system[_-]?prompt|private[_-]?key|"
    r"access[_-]?token|refresh[_-]?token)\b",
    re.IGNORECASE,
)

REAL_EXECUTION_SINK = re.compile(
    r"("
    r"\beval\s*\(|"
    r"\bFunction\s*\(|"
    r"\bchild_process\s*\.\s*exec(?:File|Sync)?\s*\(|"
    r"\bexec(?:File|Sync)?\s*\(|"
    r"\bspawn(?:Sync)?\s*\(|"
    r"\bvm\s*\.\s*run(?:InNewContext|InContext)\s*\(|"
    r"\bsubprocess\s*\.\s*run\s*\(|"
    r"\bsubprocess\s*\.\s*Popen\s*\(|"
    r"\bos\s*\.\s*system\s*\(|"
    r"\b[a-zA-Z_]\w*\s*\.\s*execute\s*\("
    r")",
    re.IGNORECASE,
)

REGEXP_EXEC = re.compile(
    r"(?:\.|\bRegExp\s*\([^)]*\))\s*exec\s*\(",
    re.IGNORECASE,
)

EMAIL_SEND = re.compile(
    r"\b("
    r"sendMail|send_email|smtp|nodemailer|mail\.send|"
    r"transporter\.send|email\.send"
    r")\b",
    re.IGNORECASE,
)


def classify_context(filepath: str) -> tuple[str, str]:
    p = str(filepath).replace("\\", "/").lower()
    name = Path(filepath).name.lower()

    if "/data/static/i18n/" in p:
        return "TRANSLATION_CONTENT", "Localized static content"

    if "/data/static/" in p and (
        name.endswith(".yml")
        or name.endswith(".yaml")
        or name.endswith(".json")
    ):
        return "CHALLENGE_CONTENT", "Static challenge/content data"

    if (
        ".spec." in name
        or ".test." in name
        or name.startswith("test_")
        or "/test/" in p
        or "/tests/" in p
        or "__tests__/" in p
    ):
        return "TEST_CODE", "Test/specification source"

    if name.endswith((".md", ".mdx", ".rst", ".txt")):
        return "DOCUMENTATION", "Documentation/text content"

    if name.endswith((".json", ".yml", ".yaml", ".xml", ".csv")):
        return "STATIC_DATA", "Static data/configuration"

    return "APPLICATION_CODE", "Application source"


def _nearby_context(lines: list[str], line_no: int, radius: int = 8) -> str:
    if not lines:
        return ""
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _context_radius(rule_id: str, vuln_type: str) -> int:
    """Return a rule-aware evidence context radius."""
    if (
        rule_id == "LLM01_PROMPT_INJECTION"
        or vuln_type == "llm_prompt_injection"
    ):
        return 20

    if (
        rule_id == "LLM02_INSECURE_OUTPUT_HANDLING"
        or vuln_type == "llm_insecure_output"
    ):
        return 20

    if (
        rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE"
        or vuln_type == "llm_sensitive_information_disclosure"
    ):
        return 16

    return 8



def _has_model_invocation(content: str) -> bool:
    """Detect common LLM/model invocation APIs across JS/TS and Python."""
    return bool(re.search(
        r"("
        r"\b(?:generateText|streamText|generateObject|streamObject)\s*\(|"
        r"\b(?:chat\.completions|responses\.create|completions\.create)\b|"
        r"\b(?:openai\.(?:chat|responses)|"
        r"anthropic\.(?:messages|completions)|"
        r"gemini\.(?:generateContent|generate_content))\b|"
        r"\b(?:model|llm|agent|chain)\s*\.\s*"
        r"(?:generate|invoke|complete|chat|run|stream|call|predict)\s*\("
        r")",
        content or "",
        re.IGNORECASE,
    ))


def _has_prompt_to_model_flow(content: str) -> bool:
    """Confirm that prompt/instruction material reaches an LLM invocation."""
    content = content or ""

    if not _has_model_invocation(content):
        return False

    # Common prompt-bearing arguments and variables.
    prompt_terms = (
        r"(prompt|user_prompt|userPrompt|user_input|userInput|"
        r"systemPrompt|system_prompt|instructions?|messages)"
    )

    # Direct call-site form, e.g. generateText(..., prompt=prompt).
    if re.search(
        r"(generateText|streamText|generateObject|streamObject|"
        r"chat\.completions|responses\.create|completions\.create)"
        r".{0,500}" + prompt_terms,
        content,
        re.IGNORECASE | re.DOTALL,
    ):
        return True

    # Construction/assignment followed by an LLM call.
    if re.search(
        prompt_terms + r".{0,700}" +
        r"(generateText|streamText|generateObject|streamObject|"
        r"chat\.completions|responses\.create|completions\.create)",
        content,
        re.IGNORECASE | re.DOTALL,
    ):
        return True

    # Generic model invocation with prompt-like content.
    return bool(re.search(
        prompt_terms + r".{0,700}\bmodel\b",
        content,
        re.IGNORECASE | re.DOTALL,
    ))


def _has_risky_prompt_injection_flow(content: str) -> bool:
    """Detect confirmed prompt-injection flows.

    Supports:
      1. indirect injection through retrieved/external content, and
      2. direct injection where user-controlled input is combined with
         explicit instruction-manipulation language before an LLM flow.

    A normal user prompt passed to a model is NOT considered a confirmed
    prompt-injection vulnerability by itself.
    """
    content = content or ""

    if not _has_prompt_to_model_flow(content):
        return False

    # ------------------------------------------------------------------
    # Explicit instruction-manipulation language.
    # ------------------------------------------------------------------
    injection_language = (
        r"(ignore\s+(?:all\s+|any\s+|the\s+)?previous\s+instructions?|"
        r"ignore\s+instructions?|"
        r"disregard\s+(?:all\s+|any\s+|the\s+)?previous\s+instructions?|"
        r"disregard\s+instructions?|"
        r"reveal\s+(?:the\s+)?system\s+prompt|"
        r"reveal\s+(?:the\s+)?hidden\s+prompt|"
        r"system\s+prompt\s+extraction|"
        r"jailbreak|"
        r"override\s+(?:the\s+)?instructions?|"
        r"bypass\s+(?:the\s+)?instructions?|"
        r"forget\s+(?:all\s+|any\s+|the\s+)?previous\s+instructions?)"
    )

    # ------------------------------------------------------------------
    # 1. Indirect / external-content prompt injection
    #
    # External/user-controlled content alone is NOT enough.
    # Require explicit instruction-manipulation language as well.
    # ------------------------------------------------------------------
    external = (
        r"(document|retrieved|retrieval|external[_-]?content|uploaded|"
        r"req\.(body|query|params)|request\.(body|query|params)|"
        r"complaint\.message|untrusted|third[_-]party)"
    )

    prompt = (
        r"(systemPrompt|system_prompt|system\s*:|instructions?|"
        r"prompt\s*=|messages\s*=|messages\s*:|prompt\s*:)"
    )

    if re.search(
        external + r".{0,700}" + injection_language +
        r".{0,700}" + prompt + r".{0,700}" +
        r"(generateText|streamText|generateObject|streamObject|"
        r"chat\.completions|responses\.create|completions\.create|model)",
        content,
        re.IGNORECASE | re.DOTALL,
    ):
        return True

    # ------------------------------------------------------------------
    # 2. Direct user-controlled prompt injection
    #
    # Require:
    #   a) user-controlled prompt/input
    #   b) explicit instruction-manipulation language
    #   c) prompt/model context
    # ------------------------------------------------------------------
    user_input = (
        r"(user_prompt|userPrompt|user_input|userInput|"
        r"req\.body|req\.query|req\.params|request\.body|"
        r"request\.query|request\.params)"
    )

    prompt_context = (
        r"(prompt|systemPrompt|system_prompt|instructions?|"
        r"generateText|streamText|generateObject|streamObject|"
        r"chat\.completions|responses\.create|completions\.create)"
    )

    direct_flow = (
        user_input + r".{0,700}" + injection_language +
        r".{0,700}" + prompt_context
    )

    reverse_direct_flow = (
        injection_language + r".{0,700}" + prompt_context +
        r".{0,700}" + user_input
    )

    return bool(
        re.search(
            direct_flow,
            content,
            re.IGNORECASE | re.DOTALL,
        )
        or re.search(
            reverse_direct_flow,
            content,
            re.IGNORECASE | re.DOTALL,
        )
    )


def _llm_group_key(finding: dict, content: str) -> str | None:
    """
    Assign a stable group key only to validated LLM application workflows.

    Requires:
      - an LLM/agent rule or LLM vulnerability type
      - a real model/LLM invocation
      - messages/prompt context
      - system-prompt context
      - tool configuration

    Supports both:
      tools: [...]
      tools = [...]
    """
    rule_id = str(finding.get("rule_id", ""))
    vuln_type = str(finding.get("vuln_type", ""))

    if not (
        rule_id.startswith(("LLM", "AGENT_"))
        or vuln_type.startswith("llm_")
        or vuln_type.startswith("agent_")
    ):
        return None

    text = content or ""

    has_llm_invocation = re.search(
        r"(?:\b(?:streamText|generateText|generateObject|streamObject)\s*\(|"
        r"\b(?:chat\.completions|responses\.create|completions\.create)\b|"
        r"\b(?:openai\.(?:chat|responses)|anthropic\.(?:messages|completions)|"
        r"gemini\.(?:generateContent|generate_content))\b|"
        r"\b(?:model|llm|agent|chain)\s*\.\s*"
        r"(?:generate|invoke|complete|chat|run|stream|call|predict)\s*\()",
        text,
        re.IGNORECASE,
    )

    has_messages = re.search(
        r"\bmessages\b",
        text,
        re.IGNORECASE,
    )

    has_system_prompt = re.search(
        r"\b(?:systemPrompt|system_prompt|buildSystemPrompt)\b",
        text,
        re.IGNORECASE,
    )

    has_tools = re.search(
        r"\btools\s*[:=]",
        text,
        re.IGNORECASE,
    )

    if (
        has_llm_invocation
        and has_messages
        and has_system_prompt
        and has_tools
    ):
        return "llm.chatbot.security_flow"

    return None


def refine_finding(finding: dict, content: str) -> dict:
    out = dict(finding)

    filepath = str(finding.get("file", ""))
    context_class, context_reason = classify_context(filepath)

    out["context_class"] = context_class
    out["context_reason"] = context_reason
    out.setdefault("raw_llm_finding", True)

    # Default: retain the scanner's original classification.
    actionable = True
    relevance = "HIGH"

    rule_id = str(finding.get("rule_id", ""))
    vuln_type = str(finding.get("vuln_type", ""))
    snippet = str(finding.get("snippet", "") or "")

    try:
        line_no = int(finding.get("line") or 0)
    except Exception:
        line_no = 0

    lines = content.splitlines()
    radius = _context_radius(rule_id, vuln_type)
    nearby = _nearby_context(lines, line_no, radius)
    evidence_context = f"{snippet}\n{nearby}"

    # Structured precision metadata is observational only.
    # It must not alter actionable/relevance/grouping decisions.
    out["precision_metadata"] = {
        "has_model_invocation": _has_model_invocation(content),
        "has_prompt_flow": _has_prompt_to_model_flow(content),
        "context_window_size": len(nearby.splitlines()),
    }

    # Static challenge/localization/test material is preserved as raw
    # detection but is not an actionable application vulnerability.
    if context_class in {
        "CHALLENGE_CONTENT",
        "TRANSLATION_CONTENT",
        "DOCUMENTATION",
    }:
        actionable = False
        relevance = "CONTEXTUAL"

    # Test code is retained but treated conservatively.
    elif context_class == "TEST_CODE":
        actionable = False
        relevance = "TEST_CONTEXT"

    # Direct/indirect prompt injection needs a confirmed risky prompt flow.
    elif rule_id == "LLM01_PROMPT_INJECTION" or vuln_type == "llm_prompt_injection":
        if not _has_risky_prompt_injection_flow(content):
            actionable = False
            relevance = "NO_CONFIRMED_PROMPT_INJECTION_FLOW"

    # LLM06 must have actual LLM/model/prompt context and a disclosure sink.
    elif rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE":
        if not LLM_CONTEXT_TERMS.search(evidence_context):
            actionable = False
            relevance = "NO_LLM_CONTEXT"
        elif not (
            SENSITIVE_TERMS.search(evidence_context)
            and re.search(
                r"(print\s*\(|console\.(log|error|warn)\s*\(|"
                r"return\b|response\b|res\.(send|json)|"
                r"localStorage|sessionStorage|"
                r"system[_-]?prompt)",
                evidence_context,
                re.IGNORECASE,
            )
        ):
            actionable = False
            relevance = "NO_CONFIRMED_DISCLOSURE_SINK"

    # Prompt-template secret exposure needs both prompt/template semantics
    # and an actual sensitive value/reference.
    elif vuln_type == "prompt_template_secret_exposure":
        if not (
            re.search(
                r"\b(prompt|template|system[_-]?prompt)\b",
                evidence_context,
                re.IGNORECASE,
            )
            and SENSITIVE_TERMS.search(evidence_context)
        ):
            actionable = False
            relevance = "LOW_CONTEXT_CONFIDENCE"

    # Prompt/response logging needs LLM context plus sensitive material.
    elif vuln_type in {
        "prompt_response_logging_sensitive_data",
        "llm_sensitive_information_disclosure",
    }:
        if not (
            LLM_CONTEXT_TERMS.search(evidence_context)
            and SENSITIVE_TERMS.search(evidence_context)
        ):
            actionable = False
            relevance = "LOW_CONTEXT_CONFIDENCE"

    # Agent email exfiltration needs email capability AND sensitive data
    # evidence; an ordinary email variable is insufficient.
    elif (
        rule_id == "AGENT_EMAIL_EXFILTRATION"
        or vuln_type == "agent_email_exfiltration"
    ):
        if not (
            EMAIL_SEND.search(evidence_context)
            and SENSITIVE_TERMS.search(evidence_context)
            and LLM_CONTEXT_TERMS.search(evidence_context)
        ):
            actionable = False
            relevance = "LOW_CONTEXT_CONFIDENCE"

    # LLM insecure output handling requires a real execution sink.
    elif (
        rule_id == "LLM02_INSECURE_OUTPUT_HANDLING"
        or vuln_type == "llm_insecure_output"
    ):
        # LLM02 is only actionable when the file actually contains an LLM
        # context. Generic eval()/execute() code must remain non-actionable.
        if not LLM_CONTEXT_TERMS.search(evidence_context):
            actionable = False
            relevance = "NO_LLM_CONTEXT"
        elif REGEXP_EXEC.search(snippet) and not REAL_EXECUTION_SINK.search(snippet):
            actionable = False
            relevance = "REGEXP_EXEC_FALSE_POSITIVE"
        elif not REAL_EXECUTION_SINK.search(evidence_context):
            actionable = False
            relevance = "NO_CONFIRMED_EXECUTION_SINK"

    out["actionable"] = actionable
    out["security_relevance"] = relevance

    # Preserve a stable root-cause group for validated LLM application
    # workflows. Only actionable findings receive this key so contextual
    # findings cannot influence final deduplication/grouping.
    if actionable:
        group_key = _llm_group_key(finding, content)
        if group_key:
            out["group_key"] = group_key

    return out

def classify_findings(findings: list[dict], file_cache: dict[str, str]) -> list[dict]:
    result = []
    for finding in findings:
        path = str(finding.get("file", ""))
        content = file_cache.get(path, "")
        result.append(refine_finding(finding, content))
    return result
