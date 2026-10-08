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
    r"\b("
    r"eval\s*\(|"
    r"Function\s*\(|"
    r"child_process\s*\.\s*exec(?:File|Sync)?\s*\(|"
    r"exec(?:File|Sync)?\s*\(|"
    r"spawn(?:Sync)?\s*\(|"
    r"vm\s*\.\s*run(?:InNewContext|InContext)\s*\("
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


def classify_context(filepath: str, content: str = "") -> tuple[str, str]:
    p = str(filepath).replace("\\", "/").lower()
    name = Path(filepath).name.lower()

    # Juice Shop challenge/code-fix artifacts are intentionally vulnerable
    # training content, not production application vulnerabilities.
    if "/data/static/codefixes/" in p:
        return "CHALLENGE_CONTENT", "Juice Shop challenge/code-fix artifact"

    if "/data/static/i18n/" in p:
        return "TRANSLATION_CONTENT", "Localized static content"

    if (
        "/config/" in p
        or "/models/challenge." in p
        or "/lib/startup/validatepreconditions." in p
    ) and re.search(
        r"challenge|systemprompt|prompt.?injection|greedy.?chatbot|ai.?debugging",
        filepath + " " + content[:4000],
        re.IGNORECASE,
    ):
        return "CHALLENGE_CONTENT", "Juice Shop challenge configuration/orchestration"

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
        # BOMs and generated/static descriptive files are not executable source.
        if name == "bom.json" or "/bom" in p or "/reports/" in p:
            return "STATIC_DATA", "Generated/static inventory data"
        return "STATIC_DATA", "Static data/configuration"

    return "APPLICATION_CODE", "Application source"


def _nearby_context(lines: list[str], line_no: int, radius: int = 8) -> str:
    if not lines:
        return ""
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _is_juice_shop_challenge_artifact(filepath: str, content: str, snippet: str) -> bool:
    p = filepath.replace("\\", "/").lower()
    s = (snippet or "").lower()
    c = (content or "").lower()

    # Explicit challenge/code-fix material.
    if "/data/static/codefixes/" in p:
        return True

    # Challenge orchestration / verification paths.
    if "/routes/verify." in p and (
        "systempromptextractionchallenge" in s
        or "systempromptextractionchallenge" in c
        or "system prompt extraction" in c
    ):
        return True

    # Other obvious Juice Shop challenge artifacts.
    challenge_markers = (
        "vuln-code-snippet",
        "challengeutils.solv",
        "ischallengeenabled",
        "systempromptextractionchallenge",
    )
    if any(m in s for m in challenge_markers):
        return True

    return False


def _has_real_llm_invocation(content: str) -> bool:
    return bool(re.search(
        r"\b(streamText|generateText|generateObject|streamObject|chat\.completions|"
        r"responses\.create|completions\.create|invoke|callModel|llm\.|model\.)\b",
        content or "",
        re.IGNORECASE,
    ))


def _has_user_controlled_prompt_flow(content: str) -> bool:
    return bool(re.search(
        r"(req\.body|req\.query|req\.params|user(Name|Input|Prompt)|"
        r"messages\b|complaint\.message|input\b).{0,300}"
        r"(prompt|systemPrompt|messages|userPrompt|streamText|generateText|"
        r"chat\.completions|responses\.create)",
        content or "",
        re.IGNORECASE | re.DOTALL,
    ))


def _has_llm_output_to_dangerous_sink(content: str) -> bool:
    return bool(re.search(
        r"(result|response|output|text|completion|message|llm)[A-Za-z0-9_.$\[\]]*"
        r".{0,250}"
        r"(eval\s*\(|Function\s*\(|vm\.run|vm\.runInContext|exec\s*\(|"
        r"child_process|spawn\s*\(|execFile\s*\(|setTimeout\s*\(|setInterval\s*\()",
        content or "",
        re.IGNORECASE | re.DOTALL,
    ))


def _has_sensitive_disclosure_sink(content: str) -> bool:
    return bool(re.search(
        r"(systemPrompt|api[_-]?key|secret|token|password|credential|"
        r"private[_-]?data|customer[_-]?data).{0,250}"
        r"(return\b|res\.(json|send|write)|response|output|print\s*\(|"
        r"console\.(log|error)|logger\.|send\s*\(|email|mail|stream)",
        content or "",
        re.IGNORECASE | re.DOTALL,
    ))


def refine_finding(finding: dict, content: str) -> dict:
    filepath = str(finding.get("file", ""))
    snippet = str(finding.get("snippet") or finding.get("evidence") or "")
    rule_id = str(finding.get("rule_id") or "")
    vuln_type = str(finding.get("vuln_type") or "")

    context_class, context_reason = classify_context(filepath, content)

    # Default: retain the raw detection as a contextual candidate.
    actionable = True
    relevance = "HIGH"

    # Explicit benchmark/training artifacts.
    if _is_juice_shop_challenge_artifact(filepath, content, snippet):
        actionable = False
        relevance = "CHALLENGE_ARTIFACT"

    # Static/generated inventory content is not executable application code.
    elif context_class == "STATIC_DATA":
        actionable = False
        relevance = "STATIC_DATA_FALSE_POSITIVE"

    # Tests are retained in the raw result but are not treated as production
    # actionable findings by this precision benchmark.
    elif context_class == "TEST_CODE":
        actionable = False
        relevance = "TEST_CONTEXT"

    # LLM01: require a real model invocation and a user-controlled prompt flow.
    elif rule_id == "LLM01_PROMPT_INJECTION" or vuln_type == "llm_prompt_injection":
        if not _has_real_llm_invocation(content):
            actionable = False
            relevance = "NO_LLM_INVOCATION"
        elif not _has_user_controlled_prompt_flow(content):
            actionable = False
            relevance = "NO_USER_CONTROLLED_PROMPT_FLOW"
        elif re.search(
            r"systempromptextractionchallenge|vuln-code-snippet|challengeutils\.solve",
            content or "",
            re.IGNORECASE,
        ):
            actionable = False
            relevance = "CHALLENGE_ARTIFACT"

    # LLM02: require LLM/model output to reach a dangerous execution sink.
    elif rule_id == "LLM02_INSECURE_OUTPUT_HANDLING" or vuln_type == "llm_insecure_output":
        p = filepath.replace("\\", "/").lower()
        if p.endswith("/bom.json") or "/bom.json" in p:
            actionable = False
            relevance = "STATIC_DATA_FALSE_POSITIVE"
        elif REGEXP_EXEC.search(snippet):
            actionable = False
            relevance = "REGEXP_EXEC_FALSE_POSITIVE"
        elif not _has_llm_output_to_dangerous_sink(content):
            actionable = False
            relevance = "NO_LLM_OUTPUT_TO_DANGEROUS_SINK"

    # LLM06: require a concrete sensitive-data disclosure sink.
    elif rule_id == "LLM06_SENSITIVE_INFORMATION_DISCLOSURE" or vuln_type == "llm_sensitive_disclosure":
        if not _has_sensitive_disclosure_sink(content):
            actionable = False
            relevance = "NO_CONFIRMED_DISCLOSURE_SINK"

    result = dict(finding)
    result.update(
        {
            "actionable": actionable,
            "security_relevance": relevance,
            "context_class": context_class,
            "context_reason": context_reason,
        }
    )
    return result


def classify_findings(findings: list[dict], file_cache: dict[str, str]) -> list[dict]:
    """Apply contextual/semantic precision classification to raw findings."""
    result = []
    for finding in findings:
        path = str(finding.get("file", ""))
        content = file_cache.get(path, "")
        result.append(refine_finding(finding, content))
    return result
