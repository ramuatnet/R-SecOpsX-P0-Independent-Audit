from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

if not TARGET.exists():
    raise SystemExit(f"ERROR: Target not found: {TARGET}")

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

source = TARGET.read_text(encoding="utf-8-sig")

# ------------------------------------------------------------------
# 1. Add AST import
# ------------------------------------------------------------------

if "import ast\n" not in source:
    source = source.replace(
        "from __future__ import annotations\n\n",
        "from __future__ import annotations\n\nimport ast\n",
        1,
    )

# ------------------------------------------------------------------
# 2. Add AST component mappings and helpers
# ------------------------------------------------------------------

anchor = "\ndef _make_aibom_item("

if "_AI_AST_COMPONENTS = {" not in source:

    ast_block = r'''

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
            )
        )

        findings[-1]["import_resolution"] = resolution

    return findings

'''

    if anchor not in source:
        raise SystemExit(
            "ERROR: Expected _make_aibom_item anchor was not found. "
            "No source change made."
        )

    source = source.replace(anchor, ast_block + anchor, 1)

# ------------------------------------------------------------------
# 3. Add AST findings after regex discovery
# ------------------------------------------------------------------

old = '''    return deduplicate(findings)


def deduplicate(items: list[dict]) -> list[dict]:
'''

new = '''    # V11 P0.1:
    # AST/import resolution augments legacy regex discovery.
    # Regex remains the fallback/supplementary mechanism.
    if path.suffix.lower() == ".py":
        findings.extend(_ast_findings(path, source))

    return deduplicate(findings)


def deduplicate(items: list[dict]) -> list[dict]:
'''

if old not in source:
    raise SystemExit(
        "ERROR: Expected scan_file return block was not found. "
        "No source change made."
    )

source = source.replace(old, new, 1)

# ------------------------------------------------------------------
# 4. Preserve AST import resolution during deduplication
# ------------------------------------------------------------------

old = '''        if key in seen:
            continue

        seen.add(key)
        final.append(item)
'''

new = '''        if key in seen:
            # Preserve AST-derived import resolution when the same
            # finding was already discovered by legacy regex.
            for existing in final:
                existing_key = (
                    existing.get("provider"),
                    existing.get("component"),
                    existing.get("file"),
                    existing.get("line"),
                    existing.get("evidence"),
                )

                if existing_key == key:
                    resolution = item.get("import_resolution")

                    if resolution and not existing.get(
                        "import_resolution"
                    ):
                        existing["import_resolution"] = resolution

                    break

            continue

        seen.add(key)
        final.append(item)
'''

if old not in source:
    raise SystemExit(
        "ERROR: Expected deduplication block was not found. "
        "No source change made."
    )

source = source.replace(old, new, 1)

# ------------------------------------------------------------------
# 5. Backup
# ------------------------------------------------------------------

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"aibom.py.before_ast_import_resolution_{timestamp}.py"
backup.write_text(source if False else TARGET.read_text(encoding="utf-8-sig"), encoding="utf-8")

# ------------------------------------------------------------------
# 6. Write patched source
# ------------------------------------------------------------------

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Added AI-BOM Python AST verification")
print("[PASS] Added imported-module resolution")
print("[PASS] Added import alias resolution")
print("[PASS] Added imported-class method resolution")
print("[PASS] Preserved regex fallback")
print(f"[BACKUP] {backup}")
