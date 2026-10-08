from __future__ import annotations

import re
from pathlib import Path
from scanner.sast import _skip


SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".cs", ".env", ".yml", ".yaml", ".json",
    ".toml", ".ini", ".config"
}


AI_RULES = [
    {
        "provider": "OpenAI",
        "component": "OpenAI SDK / API",
        "patterns": [
            r"\bimport\s+openai\b",
            r"\bfrom\s+openai\s+import\b",
            r"\bOpenAI\s*\(",
            r"\bopenai\.ChatCompletion\b",
            r"\bopenai\.Completion\b",
            r"\bapi\.openai\.com\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate prompt/data handling, API key storage, logging, and model governance."
    },
    {
        "provider": "Azure OpenAI",
        "component": "Azure OpenAI",
        "patterns": [
            r"\bAzureOpenAI\s*\(",
            r"\bazure\.ai\.openai\b",
            r"\bopenai\.azure\.com\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate Azure OpenAI deployment, private networking, logging, and data residency controls."
    },
    {
        "provider": "Anthropic",
        "component": "Anthropic Claude SDK / API",
        "patterns": [
            r"\bimport\s+anthropic\b",
            r"\bfrom\s+anthropic\s+import\b",
            r"\bAnthropic\s*\(",
            r"\bapi\.anthropic\.com\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate prompt injection controls, data sharing, API key security, and model usage governance."
    },
    {
        "provider": "Google",
        "component": "Google Gemini / Generative AI",
        "patterns": [
            r"\bgoogle\.generativeai\b",
            r"\bgenai\.GenerativeModel\b",
            r"\bgemini-pro\b",
            r"\bgemini-1",
            r"\baiplatform\.gapic\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate data processing region, prompt logging, model access controls, and safety settings."
    },
    {
        "provider": "HuggingFace",
        "component": "HuggingFace Transformers",
        "patterns": [
            r"\bfrom\s+transformers\s+import\b",
            r"\bimport\s+transformers\b",
            r"\bAutoModel\b",
            r"\bAutoTokenizer\b",
            r"\bpipeline\s*\(",
            r"\bhuggingface\.co\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate model provenance, license, unsafe model loading, and dependency trust."
    },
    {
        "provider": "LangChain",
        "component": "LangChain Framework",
        "patterns": [
            r"\bimport\s+langchain\b",
            r"\bfrom\s+langchain\b",
            r"\bLangChain\b",
            r"\bChatOpenAI\b",
            r"\bLLMChain\b",
            r"\bAgentExecutor\b",
        ],
        "risk": "HIGH",
        "recommendation": "Validate tool permissions, prompt injection controls, memory handling, and external data access."
    },
    {
        "provider": "LlamaIndex",
        "component": "LlamaIndex Framework",
        "patterns": [
            r"\bimport\s+llama_index\b",
            r"\bfrom\s+llama_index\b",
            r"\bGPTVectorStoreIndex\b",
            r"\bVectorStoreIndex\b",
        ],
        "risk": "HIGH",
        "recommendation": "Validate RAG data sources, embedding storage, access control, and data leakage risks."
    },
    {
        "provider": "Ollama",
        "component": "Ollama Local LLM",
        "patterns": [
            r"\bimport\s+ollama\b",
            r"\bollama\.chat\b",
            r"\bollama\.generate\b",
            r"\blocalhost:11434\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate local model provenance, exposed endpoints, and sensitive prompt handling."
    },
    {
        "provider": "Mistral",
        "component": "Mistral AI",
        "patterns": [
            r"\bimport\s+mistralai\b",
            r"\bfrom\s+mistralai\b",
            r"\bMistralClient\b",
            r"\bapi\.mistral\.ai\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate model usage, API key protection, data retention, and prompt governance."
    },
    {
        "provider": "Cohere",
        "component": "Cohere AI",
        "patterns": [
            r"\bimport\s+cohere\b",
            r"\bcohere\.Client\b",
            r"\bapi\.cohere\.ai\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate prompt/data handling, API key security, and vendor governance."
    },
    {
        "provider": "DeepSeek",
        "component": "DeepSeek AI",
        "patterns": [
            r"\bdeepseek\b",
            r"\bapi\.deepseek\.com\b",
        ],
        "risk": "MEDIUM",
        "recommendation": "Validate data residency, vendor governance, and sensitive data handling."
    },
    {
        "provider": "CrewAI",
        "component": "CrewAI Agent Framework",
        "patterns": [
            r"\bimport\s+crewai\b",
            r"\bfrom\s+crewai\b",
            r"\bAgent\s*\(",
            r"\bCrew\s*\(",
            r"\bTask\s*\(",
        ],
        "risk": "HIGH",
        "recommendation": "Validate agent permissions, tool access, memory, and autonomous action boundaries."
    },
    {
        "provider": "AutoGen",
        "component": "Microsoft AutoGen Agent Framework",
        "patterns": [
            r"\bimport\s+autogen\b",
            r"\bfrom\s+autogen\b",
            r"\bAssistantAgent\b",
            r"\bUserProxyAgent\b",
        ],
        "risk": "HIGH",
        "recommendation": "Validate multi-agent tool execution, human approval gates, and data leakage controls."
    },
]


MODEL_HINT_RE = re.compile(
    r"(model|deployment|engine)\s*[=:]\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE
)


def _should_scan(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in SCANNABLE_EXT


def _line_for_offset(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def _make_aibom_item(rule: dict, filepath: str, line: int, evidence: str, model_hint: str | None = None) -> dict:
    return {
        "bom_type": "AI-BOM",
        "provider": rule["provider"],
        "component": rule["component"],
        "model_hint": model_hint or "",
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
    }


def _nearby_model_hint(lines: list[str], line_no: int) -> str | None:
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 3)

    window = "\n".join(lines[start:end])

    match = MODEL_HINT_RE.search(window)

    if match:
        return match.group(2)

    return None


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = []
    lines = source.splitlines()

    for rule in AI_RULES:
        compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in rule["patterns"]
        ]

        for pattern in compiled_patterns:
            for match in pattern.finditer(source):
                line_no = _line_for_offset(source, match.start())
                evidence = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""

                if evidence.lstrip().startswith(("#", "//", "*")):
                    continue

                model_hint = _nearby_model_hint(lines, line_no)

                findings.append(
                    _make_aibom_item(
                        rule,
                        str(path),
                        line_no,
                        evidence,
                        model_hint
                    )
                )

    return deduplicate(findings)


def deduplicate(items: list[dict]) -> list[dict]:
    seen = set()
    final = []

    for item in items:
        key = (
            item.get("provider"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
            item.get("evidence"),
        )

        if key in seen:
            continue

        seen.add(key)
        final.append(item)

    return final


def generate_aibom(target_path: str) -> list[dict]:
    target = Path(target_path)

    results = []

    if target.is_file():
        if _skip(target):
            return []
        return scan_file(str(target))

    if not target.exists():
        return []

    for path in target.rglob("*"):
        if _skip(path):
            continue

        if _should_scan(path):
            results.extend(scan_file(str(path)))

    return deduplicate(results)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="aibom.json")
    args = parser.parse_args()

    aibom = generate_aibom(args.target)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(aibom, f, indent=2)

    print(f"[AI-BOM] Items found: {len(aibom)}")
    print(f"[AI-BOM] Output written: {args.output}")