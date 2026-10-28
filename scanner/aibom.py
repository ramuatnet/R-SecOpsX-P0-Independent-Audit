from __future__ import annotations

import ast
import json
import os
import re
import hashlib
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen
from urllib.error import HTTPError

from scanner.sast import _skip
# T-0.2 (task.md): the one walk's index; no engine re-walks the tree.
from core import file_index


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




# ---------------------------------------------------------------------------
# V11 AI-BOM P0.5 — AST MODEL RESOLUTION
# ---------------------------------------------------------------------------

_AIBOM_MODEL_KEYWORDS = {
    "model",
    "deployment",
    "model_name",
    "model_id",
    "engine",
}


def _aibom_string_constant(node):
    """
    Return a statically resolvable Python string constant.

    Python 3.14 compatibility:
      - Use ast.Constant rather than the removed ast.Str API.
      - Return None for non-string expressions.
      - Do not evaluate arbitrary expressions.
    """
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            return value

    return None

def _aibom_getenv_reference(node):
    """
    Resolve:
        os.getenv("OPENAI_MODEL")
        os.environ.get("OPENAI_MODEL")
    """
    if not isinstance(node, ast.Call):
        return None

    func = node.func

    if isinstance(func, ast.Attribute):
        if (
            func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            if node.args:
                return _aibom_string_constant(node.args[0])

        if (
            func.attr == "get"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "environ"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "os"
        ):
            if node.args:
                return _aibom_string_constant(node.args[0])

    return None


def _aibom_build_model_symbols(tree):
    """
    Build a conservative Python symbol table for model values.

    Supported:
      MODEL = "gpt-5"
      MODEL = OTHER_MODEL
      MODEL = os.getenv("OPENAI_MODEL")

    Deliberately unsupported:
      MODEL = get_model()
      MODEL = foo.bar()
      arbitrary inter-procedural execution
    """
    symbols = {}

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):
            targets = node.targets

        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]

        else:
            continue

        value = node.value

        for target in targets:
            if not isinstance(target, ast.Name):
                continue

            name = target.id

            literal = _aibom_string_constant(value)

            if literal is not None:
                symbols[name] = {
                    "value": literal,
                    "reference": None,
                    "resolution": "RESOLVED",
                    "source": "AST_CONSTANT",
                }
                continue

            env_reference = _aibom_getenv_reference(value)

            if env_reference:
                symbols[name] = {
                    "value": None,
                    "reference": env_reference,
                    "resolution": "PARTIAL",
                    "source": "ENVIRONMENT_VARIABLE",
                }
                continue

            if isinstance(value, ast.Name):
                symbols[name] = {
                    "value": None,
                    "reference": value.id,
                    "resolution": "SYMBOL_REFERENCE",
                    "source": "AST_VARIABLE",
                }
                continue

            symbols[name] = {
                "value": None,
                "reference": None,
                "resolution": "UNKNOWN",
                "source": "DYNAMIC_EXPRESSION",
            }

    return symbols


def _aibom_resolve_model_value(node, symbols, seen=None):
    """
    Resolve an AST expression to a model descriptor.

    Returns:
        value
        reference
        resolution
        source
    """
    if seen is None:
        seen = set()

    literal = _aibom_string_constant(node)

    if literal is not None:
        return {
            "value": literal,
            "reference": None,
            "resolution": "RESOLVED",
            "source": "AST_LITERAL",
        }

    env_reference = _aibom_getenv_reference(node)

    if env_reference:
        return {
            "value": None,
            "reference": env_reference,
            "resolution": "PARTIAL",
            "source": "ENVIRONMENT_VARIABLE",
        }

    if isinstance(node, ast.Name):
        name = node.id

        if name in seen:
            return {
                "value": None,
                "reference": name,
                "resolution": "UNKNOWN",
                "source": "CYCLIC_REFERENCE",
            }

        entry = symbols.get(name)

        if not entry:
            return {
                "value": None,
                "reference": name,
                "resolution": "UNKNOWN",
                "source": "UNRESOLVED_VARIABLE",
            }

        if entry.get("resolution") == "SYMBOL_REFERENCE":
            seen.add(name)

            target = entry.get("reference")

            target_node = None

            for symbol_name, symbol_entry in symbols.items():
                if symbol_name == target:
                    target_node = symbol_name
                    break

            if target_node:
                resolved = symbols[target_node]

                if resolved.get("resolution") == "RESOLVED":
                    return {
                        "value": resolved.get("value"),
                        "reference": name,
                        "resolution": "RESOLVED",
                        "source": "AST_VARIABLE",
                    }

                if resolved.get("resolution") == "PARTIAL":
                    return {
                        "value": None,
                        "reference": resolved.get("reference") or name,
                        "resolution": "PARTIAL",
                        "source": resolved.get("source"),
                    }

            return {
                "value": None,
                "reference": name,
                "resolution": "UNKNOWN",
                "source": "AST_VARIABLE",
            }

        return dict(entry)

    if isinstance(node, ast.JoinedStr):
        parts = []

        for value_node in node.values:
            if isinstance(value_node, ast.Constant):
                if isinstance(value_node.value, str):
                    parts.append(value_node.value)
                    continue

            return {
                "value": None,
                "reference": None,
                "resolution": "UNKNOWN",
                "source": "DYNAMIC_EXPRESSION",
            }

        return {
            "value": "".join(parts),
            "reference": None,
            "resolution": "RESOLVED",
            "source": "AST_LITERAL",
        }

    return {
        "value": None,
        "reference": None,
        "resolution": "UNKNOWN",
        "source": "DYNAMIC_EXPRESSION",
    }


def _aibom_extract_model_calls(source):
    """
    Extract model/deployment expressions from Python Call nodes.

    This operates independently of provider detection. The existing
    provider/AI-component detection remains unchanged.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return {}

    symbols = _aibom_build_model_symbols(tree)
    results = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for keyword in node.keywords:
            if keyword.arg not in _AIBOM_MODEL_KEYWORDS:
                continue

            resolution = _aibom_resolve_model_value(
                keyword.value,
                symbols,
            )

            # P0.5: retain the model resolution while classifying the
            # semantic model usage represented by the call.
            usage_type = "MODEL"

            if isinstance(node.func, ast.Attribute):
                call_root = node.func
                attribute_chain = []

                while isinstance(call_root, ast.Attribute):
                    attribute_chain.append(call_root.attr)
                    call_root = call_root.value

                chain = list(reversed(attribute_chain))
                chain_text = ".".join(chain).lower()

                if "embedding" in chain_text:
                    usage_type = "EMBEDDING"
                elif (
                    "chat" in chain_text
                    or "completion" in chain_text
                    or "responses" in chain_text
                ):
                    usage_type = "GENERATION"

            resolution = dict(resolution)
            resolution["usage_type"] = usage_type

            results[node.lineno] = resolution

    return results



# ---------------------------------------------------------------------------
# V11 AI-BOM P0.5 — MODEL FINDING ASSOCIATION
# ---------------------------------------------------------------------------

def _aibom_associate_model_calls(source, findings):
    """
    Associate AI component findings with one or more model/deployment calls.

    P0.5 contract:

      * Exact model-call line association.
      * Receiver-based association.
      * Multiple model calls are preserved in model_usages.
      * A single model_value remains available for compatibility.
      * Embedding usage is explicitly classified.
      * Ambiguous nearest-call association is not forced.
    """
    if not findings:
        return findings

    try:
        model_calls = _aibom_extract_model_calls(source)
    except Exception:
        return findings

    if not model_calls:
        return findings

    lines = source.splitlines()

    def _apply_usage(item, resolution):
        if not resolution:
            return

        usage = {
            "value": resolution.get("value"),
            "reference": resolution.get("reference"),
            "resolution": resolution.get("resolution"),
            "source": resolution.get("source"),
            "usage_type": resolution.get("usage_type", "MODEL"),
        }

        existing = item.get("model_usages")

        if not isinstance(existing, list):
            existing = []

        # Deduplicate structurally.
        if usage not in existing:
            existing.append(usage)

        # Stable deterministic ordering.
        existing.sort(
            key=lambda x: (
                str(x.get("usage_type") or ""),
                str(x.get("value") or ""),
                str(x.get("reference") or ""),
            )
        )

        item["model_usages"] = existing

        # Preserve the existing scalar contract.
        #
        # Prefer a resolved concrete model. If multiple concrete models
        # exist, use the first deterministic value while retaining every
        # usage in model_usages.
        concrete = [
            x for x in existing
            if x.get("value") is not None
        ]

        selected = concrete[0] if concrete else existing[0]

        item["model_value"] = selected.get("value")
        item["model_reference"] = selected.get("reference")
        item["model_resolution"] = selected.get("resolution")
        item["model_source"] = selected.get("source")
        item["model_usage_type"] = selected.get("usage_type")

        if selected.get("value"):
            item["model_hint"] = selected["value"]

    # ------------------------------------------------------------------
    # Build receiver -> ALL model calls using AST structure.
    #
    # Do not infer the receiver from source-text regex because a bounded
    # context may contain constructor/import calls before the actual API
    # call. For example:
    #
    #   client = OpenAI()
    #   response = client.chat.completions.create(
    #       model="gpt-5"
    #
    # The receiver is structurally "client", not "OpenAI".
    # ------------------------------------------------------------------
    receiver_calls = {}

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        tree = None

    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Only process calls that actually contain a model keyword
            # represented by the model-call extractor.
            if not any(
                keyword.arg in _AIBOM_MODEL_KEYWORDS
                for keyword in node.keywords
            ):
                continue

            line_no = getattr(node, "lineno", None)
            resolution = model_calls.get(line_no)

            if not resolution:
                continue

            receiver = None
            func = node.func

            # Walk Attribute(value=..., attr=...) down to the root.
            # Example:
            #   client.chat.completions.create(...)
            #
            # root = Name("client")
            while isinstance(func, ast.Attribute):
                func = func.value

            if isinstance(func, ast.Name):
                receiver = func.id

            if receiver:
                receiver_calls.setdefault(receiver, []).append(
                    (line_no, resolution)
                )

    # ------------------------------------------------------------------
    # Associate findings.
    # ------------------------------------------------------------------
    for item in findings:

        finding_line = item.get("line")

        if not isinstance(finding_line, int):
            continue

        # --------------------------------------------------------------
        # 1. Exact-line association.
        # --------------------------------------------------------------
        resolution = model_calls.get(finding_line)

        if resolution:
            _apply_usage(item, resolution)
            continue

        if not (1 <= finding_line <= len(lines)):
            continue

        finding_text = lines[finding_line - 1]

        # --------------------------------------------------------------
        # 2. Receiver association.
        #
        # Example:
        #   client = OpenAI()
        #
        # Multiple calls through the same client are intentionally retained.
        # --------------------------------------------------------------
        receiver_match = re.match(
            r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=',
            finding_text,
        )

        if receiver_match:
            receiver = receiver_match.group(1)
            candidates = receiver_calls.get(receiver, [])

            if candidates:
                for _, candidate_resolution in candidates:
                    _apply_usage(item, candidate_resolution)

                continue

        # --------------------------------------------------------------
        # 3. Controlled nearest-call fallback.
        #
        # Only associate when exactly one model call is in the bounded
        # local region.
        # --------------------------------------------------------------
        nearby = []

        for call_line, candidate_resolution in model_calls.items():
            distance = abs(call_line - finding_line)

            if distance <= 12:
                nearby.append(
                    (distance, call_line, candidate_resolution)
                )

        if len(nearby) == 1:
            _, _, candidate_resolution = nearby[0]
            _apply_usage(item, candidate_resolution)

    return findings


# ---------------------------------------------------------------------------
# END V11 AI-BOM P0.5 MODEL ASSOCIATION
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


def _aibom_apply_model_resolution(path, source, findings):
    """
    Attach structured model resolution only to findings located on an
    actual model/deployment call.

    Existing model_hint behavior is retained for compatibility.
    """
    if path.suffix.lower() != ".py":
        return findings

    model_calls = _aibom_extract_model_calls(source)

    if not model_calls:
        return findings

    # P0.5: associate model calls with AI component findings that
    # originate from client construction/import lines.
    findings = _aibom_associate_model_calls(source, findings)

    for item in findings:
        line_no = item.get("line")

        resolution = model_calls.get(line_no)

        if not resolution:
            continue

        item["model_value"] = resolution.get("value")
        item["model_reference"] = resolution.get("reference")
        item["model_resolution"] = resolution.get("resolution")
        item["model_source"] = resolution.get("source")

        if resolution.get("value"):
            item["model_hint"] = resolution["value"]

    return findings

# ---------------------------------------------------------------------------
# END V11 AI-BOM P0.5
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase 4.3 -- AI-BOM completeness scoring (G7/NTIA minimum elements) and
# HuggingFace hub metadata enrichment
# ---------------------------------------------------------------------------
# The minimum elements for an AI BOM, from the NTIA minimum-elements
# work adapted for AI models: provider, model name, model version, model
# type, release date, digital signature, training-data provenance,
# license, dependencies, deployment environment. Every item is scored
# present/total with an explicit breakdown, in the same spirit as the
# Phase-2 quality scoring: what is missing is named, and what source
# scanning can NEVER establish (digital signatures, training-data
# provenance -- those live with the model artifact, not in application
# code) is disclosed as not-computable rather than silently folded into
# the denominator as ordinary misses.
#
# HuggingFace enrichment converts three otherwise-missing elements
# (model type refinement, license, release date) into computable ones for
# hub-hosted models, by asking the public hub API for the model card
# metadata. It is fail-open and cached; RSX_HF_ENRICH=0 disables it.

# Elements source scanning cannot establish from application code by any
# amount of analysis. Disclosed, never guessed.
_AIBOM_NOT_COMPUTABLE = (
    "digital_signature",
    "training_data_provenance",
)

_AIBOM_ELEMENTS_TOTAL = 10

# Provider -> model-type element. HuggingFace models are refined to the
# hub's pipeline_tag when enrichment succeeds.
_AIBOM_PROVIDER_MODEL_TYPE = {
    "OpenAI": "hosted-llm-api",
    "Azure OpenAI": "hosted-llm-api",
    "Anthropic": "hosted-llm-api",
    "Google": "hosted-llm-api",
    "Mistral": "hosted-llm-api",
    "Cohere": "hosted-llm-api",
    "DeepSeek": "hosted-llm-api",
    "HuggingFace": "transformers",
    "Ollama": "local-llm-runtime",
    "LangChain": "agent-framework",
    "LlamaIndex": "agent-framework",
    "CrewAI": "agent-framework",
    "AutoGen": "agent-framework",
}

# Provider -> deployment-environment element; default "vendor-api".
_AIBOM_PROVIDER_ENVIRONMENT = {
    "Azure OpenAI": "azure-cloud",
    "Ollama": "local",
}

# A model version is only claimed when the name itself carries one:
# dated snapshots ("gpt-4o-2024-05-13", "-20240613") or dotted versions
# ("bert-base-uncased-v2.1"). "gpt-4o" is a NAME, not a version.
_AIBOM_VERSION_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}|-\d{6,8}|\bv?\d+(?:\.\d+)+", re.IGNORECASE)

# Strict charset for hub model ids coming out of scanned source -- the
# scanned repository is untrusted input, so "../..", schemes and query
# strings must never reach the URL builder.
_HF_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$")

_HF_API = "https://huggingface.co/api/models/"


def _aibom_element_status(item: dict) -> dict:
    """Score one AI-BOM item against the NTIA/G7 minimum elements."""
    provider = str(item.get("provider") or "")
    model = str(item.get("model_hint") or "").strip()
    hf = item.get("hf_enrichment") if isinstance(
        item.get("hf_enrichment"), dict) else {}

    present: list[str] = ["provider", "dependencies", "deployment_environment"]

    if model:
        present.append("model_name")
        if _AIBOM_VERSION_RE.search(model):
            present.append("model_version")

    model_type = hf.get("pipeline_tag") or _AIBOM_PROVIDER_MODEL_TYPE.get(provider)
    if model_type:
        present.append("model_type")

    if hf.get("license"):
        present.append("license")
    if hf.get("created_at"):
        present.append("release_date")

    missing = [
        element
        for element in ("model_name", "model_version", "model_type",
                        "release_date", "license")
        if element not in present
    ]

    values = {
        "provider": provider,
        "deployment_environment": _AIBOM_PROVIDER_ENVIRONMENT.get(
            provider, "vendor-api"),
    }
    if model:
        values["model_name"] = model
    if model_type:
        values["model_type"] = str(model_type)
    if hf.get("license"):
        values["license"] = str(hf["license"])
    if hf.get("created_at"):
        values["release_date"] = str(hf["created_at"])

    return {
        "score": round(len(present) / _AIBOM_ELEMENTS_TOTAL, 3),
        "elements_total": _AIBOM_ELEMENTS_TOTAL,
        "elements_present": sorted(present),
        "elements_missing": sorted(missing),
        "elements_enriched": sorted(
            e for e, filled in (
                ("model_type", bool(hf.get("pipeline_tag"))),
                ("license", bool(hf.get("license"))),
                ("release_date", bool(hf.get("created_at"))),
            ) if filled
        ),
        "not_computable_from_source": sorted(_AIBOM_NOT_COMPUTABLE),
        "element_values": values,
    }


def _aibom_apply_completeness(items: list[dict]) -> list[dict]:
    """Attach (or recompute) the completeness block on every item."""
    for item in items:
        if isinstance(item, dict):
            item["completeness"] = _aibom_element_status(item)
    return items


def _hf_model_id(item: dict) -> str | None:
    """The hub model id an item refers to, or None when unset/invalid."""
    for value in (item.get("model_value"), item.get("model_hint")):
        text = str(value or "").strip()
        if text and ".." not in text and _HF_ID_RE.match(text):
            return text
    return None


def _hf_fetch(model_id: str, *, timeout: float = 10.0,
              opener=None) -> dict:
    """Fetch one model card's public metadata from the hub. Fail-open."""
    url = _HF_API + quote(model_id, safe="")
    try:
        if opener is None:
            with urlopen(url, timeout=timeout) as resp:
                raw = resp.read(1_000_000)
        else:
            raw = opener(url, timeout)
        data = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(data, dict):
            return {"status": "unavailable"}
    except HTTPError as exc:
        return {"status": "not-found"} if exc.code == 404 else {
            "status": "unavailable"}
    except Exception:
        return {"status": "unavailable"}

    record: dict = {"status": "ok"}
    if data.get("pipeline_tag"):
        record["pipeline_tag"] = str(data["pipeline_tag"])
    card = data.get("cardData") if isinstance(data.get("cardData"), dict) else {}
    license_value = data.get("license") or card.get("license")
    if license_value:
        record["license"] = str(license_value)
    if data.get("createdAt"):
        record["created_at"] = str(data["createdAt"])[:10]
    return record


def enrich_hf_metadata(items: list[dict], *, timeout: float = 10.0,
                       opener=None, cache_path: Path | None = None
                       ) -> list[dict]:
    """HuggingFace hub enrichment for detected HuggingFace model usages.

    For every HuggingFace item with a concrete model id, ask the public
    hub API for the model card metadata (pipeline tag, license, creation
    date) and fold it into the item and its completeness score.

    Contract:
      * FAIL-OPEN -- network/parse failures mark the item's enrichment
        status and the score stays source-only; a scan never breaks on
        hub availability;
      * CACHED -- reports/.hf_cache.json (dirty-by-convention, like
        .vuln_cache.json) so repeated scans do not re-query;
      * HOSTILE INPUT -- model ids come from scanned source; they are
        validated against a strict charset, URL-quoted, and only the
        huggingface.co API path is ever contacted;
      * RSX_HF_ENRICH=0 disables enrichment entirely.
    """
    gate = os.environ.get("RSX_HF_ENRICH", "1").strip().lower()
    if gate in {"0", "false", "off", "no"}:
        return items

    targets = [i for i in items
               if isinstance(i, dict) and i.get("provider") == "HuggingFace"]
    if not targets:
        return items

    cache_path = cache_path or (Path("reports") / ".hf_cache.json")
    cache: dict = {}
    try:
        loaded = json.loads(cache_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            cache = loaded
    except Exception:
        cache = {}

    dirty = False
    for item in targets:
        model_id = _hf_model_id(item)
        if not model_id:
            continue

        record = cache.get(model_id)
        if not isinstance(record, dict):
            record = _hf_fetch(model_id, timeout=timeout, opener=opener)
            cache[model_id] = record
            dirty = True

        entry: dict = {"model_id": model_id,
                       "status": str(record.get("status") or "unavailable")}
        for key in ("pipeline_tag", "license", "created_at"):
            if record.get(key):
                entry[key] = record[key]
        item["hf_enrichment"] = entry
        # Recompute with the enriched elements folded in.
        item["completeness"] = _aibom_element_status(item)

    if dirty:
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:  # pragma: no cover - cache is best-effort
            pass

    return items


# ---------------------------------------------------------------------------
# END Phase 4.3 completeness / HF enrichment
# ---------------------------------------------------------------------------


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = file_index.read_source(path)
    except OSError:
        return []
    if source is None:
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

    findings = _aibom_apply_model_resolution(path, source, findings)

    # Phase 4.3: every item scores against the NTIA/G7 minimum elements.
    findings = _aibom_apply_completeness(findings)

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

    # T-0.2: index query replaces target.rglob; the skip policy is walk-time.
    for path in file_index.index_for(target).files(pred=_should_scan):
        results.extend(scan_file(str(path)))

    # Phase 4.3: dedup can change which item survives a merge, so the
    # completeness score is recomputed on the final set (idempotent).
    return _aibom_apply_completeness(deduplicate(results))


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