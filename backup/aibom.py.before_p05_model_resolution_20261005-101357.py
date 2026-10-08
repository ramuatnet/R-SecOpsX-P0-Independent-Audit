from __future__ import annotations

import ast
import re
import hashlib
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



# ------------------------------------------------------------------
# V11 P0.1 — AST / IMPORT / ALIAS RESOLUTION
#
# AST is authoritative for verified Python AI component usage.
# Regex remains the fallback/supplementary discovery mechanism.
# ------------------------------------------------------------------

_AI_AST_COMPONENTS = {
    "openai": {
        "OpenAI": "OpenAI SDK / API",
        "ChatCompletion": "OpenAI SDK / API",
        "Completion": "OpenAI SDK / API",
    },
    "azure_openai": {
        "AzureOpenAI": "Azure OpenAI",
    },
    "anthropic": {
        "Anthropic": "Anthropic Claude SDK / API",
    },
    "google": {
        "GenerativeModel": "Google Gemini / Generative AI",
    },
    "huggingface": {
        "AutoModel": "HuggingFace Transformers",
        "AutoTokenizer": "HuggingFace Transformers",
        "pipeline": "HuggingFace Transformers",
    },
    "langchain": {
        "ChatOpenAI": "LangChain Framework",
        "LLMChain": "LangChain Framework",
        "AgentExecutor": "LangChain Framework",
        "Tool": "LangChain Framework",
        "DynamicTool": "LangChain Framework",
        "StructuredTool": "LangChain Framework",
    },
    "llama_index": {
        "VectorStoreIndex": "LlamaIndex Framework",
        "GPTVectorStoreIndex": "LlamaIndex Framework",
        "ReActAgent": "LlamaIndex Framework",
    },
    "ollama": {
        "chat": "Ollama Local LLM",
        "generate": "Ollama Local LLM",
        "Client": "Ollama Local LLM",
    },
    "mistral": {
        "MistralClient": "Mistral AI",
        "Mistral": "Mistral AI",
    },
    "cohere": {
        "Client": "Cohere AI",
    },
    "crewai": {
        "Agent": "CrewAI Agent Framework",
        "Crew": "CrewAI Agent Framework",
        "Task": "CrewAI Agent Framework",
    },
    "autogen": {
        "AssistantAgent": "Microsoft AutoGen Agent Framework",
        "UserProxyAgent": "Microsoft AutoGen Agent Framework",
    },
}


def _python_import_map(tree):
    imports = {}

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):
            for item in node.names:
                imports[item.asname or item.name.split(".")[0]] = item.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""

            for item in node.names:
                if item.name == "*":
                    continue

                imports[item.asname or item.name] = (
                    f"{module}.{item.name}".strip(".")
                )

    return imports


def _aibom_framework_from_module(module):
    value = str(module or "").lower()

    if value == "openai" or value.startswith("openai."):
        return "OpenAI"

    if value == "azure.ai.openai" or value.startswith("azure.ai.openai."):
        return "Azure OpenAI"

    if value == "anthropic" or value.startswith("anthropic."):
        return "Anthropic"

    if (
        value == "google.generativeai"
        or value.startswith("google.generativeai.")
        or value == "google.ai.generativelanguage"
        or value.startswith("google.ai.generativelanguage.")
    ):
        return "Google"

    if value == "transformers" or value.startswith("transformers."):
        return "HuggingFace"

    if value == "langchain" or value.startswith("langchain."):
        return "LangChain"

    if value == "llama_index" or value.startswith("llama_index."):
        return "LlamaIndex"

    if value == "ollama" or value.startswith("ollama."):
        return "Ollama"

    if value == "mistralai" or value.startswith("mistralai."):
        return "Mistral"

    if value == "cohere" or value.startswith("cohere."):
        return "Cohere"

    if value == "crewai" or value.startswith("crewai."):
        return "CrewAI"

    if value == "autogen" or value.startswith("autogen."):
        return "AutoGen"

    return None


def _aibom_component_key(framework):
    return {
        "OpenAI": "openai",
        "Azure OpenAI": "azure_openai",
        "Anthropic": "anthropic",
        "Google": "google",
        "HuggingFace": "huggingface",
        "LangChain": "langchain",
        "LlamaIndex": "llama_index",
        "Ollama": "ollama",
        "Mistral": "mistral",
        "Cohere": "cohere",
        "CrewAI": "crewai",
        "AutoGen": "autogen",
    }.get(framework)


def _aibom_ast_attr(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        left = _aibom_ast_attr(node.value)
        return f"{left}.{node.attr}" if left else node.attr

    return ""


def _ast_findings(path: Path, source: str):
    """
    P0.1 only:
      - Python AST call verification
      - import resolution
      - import alias resolution
      - imported-class method resolution

    No component IDs, confidence, provenance or model extraction are
    introduced in this phase.
    """

    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError):
        return []

    imports = _python_import_map(tree)
    lines = source.splitlines()
    findings = []

    for node in ast.walk(tree):

        if not isinstance(node, ast.Call):
            continue

        func = node.func

        if isinstance(func, ast.Name):
            symbol = func.id
            root = func.id

        elif isinstance(func, ast.Attribute):
            symbol = func.attr
            root = _aibom_ast_attr(func).split(".")[0]

        else:
            continue

        component = None
        framework = None
        resolution = None

        # ----------------------------------------------------------
        # CASE 1 — Direct imported module
        #
        # import openai
        # openai.OpenAI(...)
        #
        # import crewai as c
        # c.Agent(...)
        # ----------------------------------------------------------

        root_module = imports.get(root, root)
        root_framework = _aibom_framework_from_module(root_module)

        if root_framework:

            component_key = _aibom_component_key(root_framework)
            mapping = _AI_AST_COMPONENTS.get(component_key, {})

            if symbol in mapping:
                component = mapping[symbol]
                framework = root_framework
                resolution = f"{symbol} -> {root_module}"

        # ----------------------------------------------------------
        # CASE 2 — Imported class / function alias
        #
        # from openai import OpenAI as MyClient
        # MyClient(...)
        #
        # from crewai import Agent as CrewAgent
        # CrewAgent(...)
        # ----------------------------------------------------------

        if component is None:

            resolved = imports.get(root, "")

            if resolved:

                parts = resolved.rsplit(".", 1)

                if len(parts) == 2:

                    resolved_module, resolved_symbol = parts
                    resolved_framework = _aibom_framework_from_module(
                        resolved_module
                    )

                    if resolved_framework:

                        component_key = _aibom_component_key(
                            resolved_framework
                        )

                        mapping = _AI_AST_COMPONENTS.get(
                            component_key, {}
                        )

                        if resolved_symbol in mapping:

                            component = mapping[resolved_symbol]
                            framework = resolved_framework
                            resolution = f"{root} -> {resolved}"

        # ----------------------------------------------------------
        # CASE 3 — Imported class / symbol method call
        #
        # from llama_index.core.agent import ReActAgent
        # ReActAgent.from_tools(...)
        #
        # from openai import OpenAI as MyClient
        # MyClient.some_method(...)
        #
        # Resolve the component from the imported root symbol,
        # not from the method name.
        # ----------------------------------------------------------

        if component is None and root in imports:

            resolved = imports.get(root, "")
            parts = resolved.rsplit(".", 1)

            if len(parts) == 2:

                resolved_module, resolved_symbol = parts
                resolved_framework = _aibom_framework_from_module(
                    resolved_module
                )

                if resolved_framework:

                    component_key = _aibom_component_key(
                        resolved_framework
                    )

                    mapping = _AI_AST_COMPONENTS.get(
                        component_key, {}
                    )

                    if resolved_symbol in mapping:

                        component = mapping[resolved_symbol]
                        framework = resolved_framework
                        resolution = f"{root} -> {resolved}"

        if not framework or not component:
            continue

        line_no = node.lineno
        evidence = (
            lines[line_no - 1]
            if 0 < line_no <= len(lines)
            else ""
        )

        rule = {
            "provider": framework,
            "component": component,
            "risk": "MEDIUM",
            "recommendation": (
                "Review AI component usage, model configuration, "
                "data handling, credentials, and security controls."
            ),
        }

        findings.append(
            _make_aibom_item(
                rule,
                str(path),
                line_no,
                evidence,
                None,
                detection_mode="AST+IMPORT_RESOLUTION",
                evidence_type=["AST", "IMPORT_RESOLUTION"],
                confidence="HIGH",
                confidence_score=0.90,
                import_resolution=resolution,
            )
        )

    return findings


def _make_aibom_item(
    rule: dict,
    filepath: str,
    line: int,
    evidence: str,
    model_hint: str | None = None,
    *,
    detection_mode: str | None = None,
    evidence_type: list[str] | None = None,
    confidence: str | None = None,
    confidence_score: float | None = None,
    import_resolution: str | None = None,
) -> dict:
    provider = str(rule["provider"])
    component = str(rule["component"])

    # P0.2:
    # Canonical semantic identity is applied centrally by
    # _aibom_apply_identity_contract().
    #
    # Do not calculate component_id here. Keeping one authoritative
    # identity generator guarantees that regex, AST, import-resolution,
    # alias-resolution, and merged findings use the same identity.

    item = {
        "bom_type": "AI-BOM",
        "provider": provider,
        "component": component,
        "model_hint": model_hint or "",
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "risk": rule["risk"],
        "recommendation": rule["recommendation"],
        "detection_mode": detection_mode,
        "evidence_type": sorted(
            set(evidence_type or [])
        ),
        "confidence": confidence,
        "confidence_score": confidence_score,
    }

    if import_resolution:
        item["import_resolution"] = import_resolution

    return item


def _nearby_model_hint(lines: list[str], line_no: int) -> str | None:
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 3)

    window = "\n".join(lines[start:end])

    match = MODEL_HINT_RE.search(window)

    if match:
        return match.group(2)

    return None



# --- V11 AI-BOM P0.2 IDENTITY / EVIDENCE CONTRACT ---

def _aibom_normalize_identity(value):
    if value is None:
        return ""
    text = str(value).strip().replace("\\", "/")
    text = re.sub(r"\s+", " ", text)
    return text.lower()


def _aibom_component_id(provider, component):
    """
    Deterministic semantic AI-BOM component identity.

    Detection line, evidence text, filepath and import-resolution
    details are intentionally excluded.

    Therefore the same semantic provider/component retains the same
    identity when detection moves to another line or is discovered
    through an import alias.
    """
    provider_key = _aibom_normalize_identity(provider)
    component_key = _aibom_normalize_identity(component)

    raw = f"{provider_key}|{component_key}"

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:20].upper()

    return f"AIBOM-COMP-{digest}"


def _aibom_evidence_types(item):
    """
    Normalize evidence provenance from existing detection fields.
    """
    values = set()

    existing = item.get("evidence_type")

    if isinstance(existing, (list, tuple, set)):
        values.update(
            str(x).strip().upper()
            for x in existing
            if str(x).strip()
        )

    detection = str(
        item.get("detection_mode") or ""
    ).strip().upper()

    if detection:
        values.update(
            x.strip()
            for x in detection.split("+")
            if x.strip()
        )

    if item.get("import_resolution"):
        values.add("IMPORT_RESOLUTION")

    if item.get("model_resolution"):
        values.add("MODEL_RESOLUTION")

    if item.get("model_hint"):
        values.add("MODEL_HINT")

    return sorted(values)


def _aibom_confidence_contract(item):
    """
    Conservative confidence classification.

    Existing confidence values are upgraded only when the
    corresponding evidence actually exists.
    """
    evidence = set(
        _aibom_evidence_types(item)
    )

    if {
        "AST",
        "IMPORT_RESOLUTION",
        "MODEL_RESOLUTION",
    }.issubset(evidence):
        return "VERY_HIGH", 0.95

    if {
        "AST",
        "IMPORT_RESOLUTION",
    }.issubset(evidence):
        return "HIGH", 0.90

    if {
        "AST",
        "MODEL_RESOLUTION",
    }.issubset(evidence):
        return "HIGH", 0.85

    if {
        "REGEX",
        "IMPORT_RESOLUTION",
    }.issubset(evidence):
        return "MEDIUM", 0.70

    if "AST" in evidence:
        return "MEDIUM", 0.65

    if "REGEX" in evidence:
        return "LOW", 0.40

    return "LOW", 0.25


def _aibom_apply_identity_contract(item):
    if not isinstance(item, dict):
        return item

    item["component_id"] = _aibom_component_id(
        item.get("provider"),
        item.get("component"),
    )

    evidence_types = _aibom_evidence_types(item)

    item["evidence_type"] = evidence_types

    confidence, confidence_score = _aibom_confidence_contract(
        item
    )

    item["confidence"] = confidence
    item["confidence_score"] = confidence_score

    return item

# --- END V11 AI-BOM P0.2 IDENTITY / EVIDENCE CONTRACT ---



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
                        model_hint,
                        detection_mode="REGEX",
                        evidence_type=["REGEX"],
                        confidence="LOW",
                        confidence_score=0.40,
                    )
                )

    # V11 P0.1:
    # AST/import resolution augments legacy regex discovery.
    # Regex remains the fallback/supplementary mechanism.
    if path.suffix.lower() == ".py":
        findings.extend(_ast_findings(path, source))

    # V11 P0.2:
    # Apply stable semantic identity and evidence/confidence
    # contract after both regex and AST/import discovery.
    for _aibom_item in findings:
        _aibom_apply_identity_contract(_aibom_item)

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
            # --------------------------------------------------------
            # V11 P0.2:
            # Preserve the strongest evidence when regex and
            # AST/import discovery identify the same semantic finding.
            # --------------------------------------------------------
            for existing in final:
                existing_key = (
                    existing.get("provider"),
                    existing.get("component"),
                    existing.get("file"),
                    existing.get("line"),
                    existing.get("evidence"),
                )

                if existing_key != key:
                    continue

                # Preserve import resolution.
                resolution = item.get("import_resolution")
                if resolution and not existing.get("import_resolution"):
                    existing["import_resolution"] = resolution

                # Merge evidence provenance.
                existing_types = set(
                    existing.get("evidence_type") or []
                )
                item_types = set(
                    item.get("evidence_type") or []
                )
                merged_types = existing_types | item_types

                if merged_types:
                    existing["evidence_type"] = sorted(merged_types)

                # Merge detection modes.
                existing_modes = set(
                    str(existing.get("detection_mode", "")).split("+")
                )
                item_modes = set(
                    str(item.get("detection_mode", "")).split("+")
                )

                existing_modes.discard("")
                item_modes.discard("")

                merged_modes = existing_modes | item_modes

                if merged_modes:
                    existing["detection_mode"] = "+".join(
                        sorted(merged_modes)
                    )

                # Preserve the stronger confidence.
                confidence_rank = {
                    "LOW": 1,
                    "MEDIUM": 2,
                    "HIGH": 3,
                    "VERY_HIGH": 4,
                }

                existing_confidence = str(
                    existing.get("confidence", "LOW")
                ).upper()

                item_confidence = str(
                    item.get("confidence", "LOW")
                ).upper()

                if confidence_rank.get(
                    item_confidence, 0
                ) > confidence_rank.get(
                    existing_confidence, 0
                ):
                    existing["confidence"] = item_confidence

                    score = item.get("confidence_score")
                    if isinstance(score, (int, float)):
                        existing["confidence_score"] = float(score)

                # If the incoming item has stronger AST/import evidence,
                # preserve its score even when confidence labels match.
                elif (
                    item.get("confidence_score") is not None
                    and existing.get("confidence_score") is not None
                    and float(item["confidence_score"])
                    > float(existing["confidence_score"])
                ):
                    existing["confidence_score"] = float(
                        item["confidence_score"]
                    )

                break

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