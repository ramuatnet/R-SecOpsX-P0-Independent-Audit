from __future__ import annotations

import re
from pathlib import Path


SCANNABLE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb"
}


ABOM_RULES = [
    {
        "framework": "LangChain",
        "component": "Agent Executor",
        "patterns": [
            r"\bAgentExecutor\b",
            r"\binitialize_agent\b",
            r"\bcreate_openai_functions_agent\b",
            r"\bcreate_react_agent\b",
        ],
        "category": "Agent Framework",
        "risk": "HIGH",
    },
    {
        "framework": "LangChain",
        "component": "Tool",
        "patterns": [
            r"\bTool\s*\(",
            r"\bDynamicTool\s*\(",
            r"\bStructuredTool\s*\(",
        ],
        "category": "Tool Execution",
        "risk": "HIGH",
    },
    {
        "framework": "CrewAI",
        "component": "Agent",
        "patterns": [
            r"\bAgent\s*\(",
        ],
        "category": "Agent Framework",
        "risk": "HIGH",
    },
    {
        "framework": "CrewAI",
        "component": "Crew",
        "patterns": [
            r"\bCrew\s*\(",
        ],
        "category": "Agent Orchestration",
        "risk": "HIGH",
    },
    {
        "framework": "CrewAI",
        "component": "Task",
        "patterns": [
            r"\bTask\s*\(",
        ],
        "category": "Agent Tasking",
        "risk": "MEDIUM",
    },
    {
        "framework": "AutoGen",
        "component": "Assistant Agent",
        "patterns": [
            r"\bAssistantAgent\s*\(",
        ],
        "category": "Agent Framework",
        "risk": "HIGH",
    },
    {
        "framework": "AutoGen",
        "component": "User Proxy Agent",
        "patterns": [
            r"\bUserProxyAgent\s*\(",
        ],
        "category": "Agent Framework",
        "risk": "HIGH",
    },
    {
        "framework": "LlamaIndex",
        "component": "Query Engine",
        "patterns": [
            r"\bas_query_engine\s*\(",
            r"\bVectorStoreIndex\b",
            r"\bGPTVectorStoreIndex\b",
        ],
        "category": "Retrieval Agent",
        "risk": "HIGH",
    },
]


TOOL_HINTS = [
    "shell",
    "filesystem",
    "file",
    "command",
    "terminal",
    "exec",
    "browser",
    "http",
    "request",
    "api",
    "database",
    "sql",
]


MEMORY_HINTS = [
    "memory",
    "conversationbuffer",
    "chatmemory",
    "vectorstore",
]


HUMAN_APPROVAL_HINTS = [
    "human",
    "approval",
    "review",
    "confirm",
    "authorize",
]



# ---------------------------------------------------------------------------
# ABOM scanning scope
# ---------------------------------------------------------------------------
# Third-party/generated content is intentionally excluded from the production
# ABOM. Benchmark/test fixtures remain scannable but are tagged validation.
#
# This prevents generic constructs such as:
#   http.Agent / https.Agent
#   gulp.task() / task()
#   TypeScript declaration comments
# from becoming false AI-agent findings.
EXCLUDED_DIRS = {
    ".git", ".svn", ".hg",
    ".venv", "venv", "env", ".env", ".tox", ".cache", "__pycache__",
    "node_modules", "vendor", "third_party",
    "build", "dist", "coverage", ".next", ".nuxt",
}

VALIDATION_DIRS = {
    "tests", "test", "examples", "example",
}

VALIDATION_FILE_HINTS = {
    "codefixes",
    "challenge",
    "challenges",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "benchmark",
}

# Generic identifiers are deliberately NOT treated as AI agent/task signals.
# These require AI/agent-specific context in the same nearby source window.
GENERIC_AGENT_RE = re.compile(
    r"\b(?:Agent|agent)\s*\(",
    re.IGNORECASE,
)
GENERIC_TASK_RE = re.compile(
    r"\bTask\s*\(",
    re.IGNORECASE,
)

AI_CONTEXT_TERMS = (
    "langchain",
    "crewai",
    "autogen",
    "llamaindex",
    "llama_index",
    "agentexecutor",
    "assistantagent",
    "userproxyagent",
    "create_react_agent",
    "create_openai_functions_agent",
    "vectorstore",
    "llm",
    "chatmodel",
    "language_model",
    "toolcalling",
    "tool_call",
    "ai-sdk",
    "@ai-sdk",
    "openai",
    "anthropic",
    "gemini",
    "vertexai",
    "generativeai",
    "prompt",
)

AI_AGENT_CONTEXT_TERMS = (
    "agent",
    "agentexecutor",
    "assistantagent",
    "userproxyagent",
    "crewai",
    "langchain",
    "autogen",
    "llamaindex",
    "llama_index",
    "toolcalling",
    "tool_call",
    "react_agent",
)

AI_TASK_CONTEXT_TERMS = (
    "agent",
    "agentexecutor",
    "crewai",
    "langchain",
    "autogen",
    "tasking",
    "task_agent",
    "agent_task",
    "llm",
    "tool",
    "prompt",
)

AI_TOOL_CONTEXT_TERMS = (
    "langchain",
    "crewai",
    "autogen",
    "llamaindex",
    "llama_index",
    "ai-sdk",
    "@ai-sdk",
    "tool(",
    "tool ",
    "structuredtool",
    "dynamictool",
    "functiontool",
    "agent",
    "llm",
)

def _path_scope(path: Path) -> str:
    """Return production, validation, or dependency scope."""
    parts = {p.lower() for p in path.parts}

    if parts.intersection({"node_modules", "vendor", "third_party"}):
        return "dependency"

    if parts.intersection(VALIDATION_DIRS):
        return "validation"

    lowered = str(path).lower().replace("\\", "/")
    if any(token in lowered for token in VALIDATION_FILE_HINTS):
        return "validation"

    return "production"


def _is_excluded(path: Path) -> bool:
    """Fast directory exclusion without reading the file."""
    return bool({p.lower() for p in path.parts}.intersection(EXCLUDED_DIRS))


def _should_scan(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in SCANNABLE_EXT
        and not _is_excluded(path)
    )


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _nearby_window(lines, line_no, radius=8):
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end]).lower()


def _tool_hints(window):
    return sorted({
        hint for hint in TOOL_HINTS
        if hint in window
    })


def _memory_hints(window):
    return sorted({
        hint for hint in MEMORY_HINTS
        if hint in window
    })


def _human_approval(window):
    return any(hint in window for hint in HUMAN_APPROVAL_HINTS)


def _contains_any(window, terms):
    return any(term in window for term in terms)


def _looks_like_comment_or_type_declaration(path: Path, evidence: str) -> bool:
    """Suppress documentation/type-definition noise."""
    stripped = evidence.strip()

    if stripped.startswith(("//", "#", "*", "/*", "*/", "/**", "* @")):
        return True

    if path.suffix.lower() == ".d.ts":
        return True

    return False


def _rule_allowed(rule, evidence, window, path):
    """
    Context gate for generic CrewAI Agent/Task and similar ambiguous patterns.

    Explicit framework-specific constructs remain high-confidence. Generic
    Agent(...) / Task(...) matches require nearby AI/agent context.
    """
    component = rule["component"].lower()
    framework = rule["framework"].lower()

    # Explicit framework signatures from ABOM_RULES are strong indicators.
    if component in {
        "agent executor",
        "assistant agent",
        "user proxy agent",
        "query engine",
        "crew",
    }:
        return True

    if framework == "langchain" and component == "tool":
        return _contains_any(window, AI_TOOL_CONTEXT_TERMS)

    if framework == "crewai" and component == "agent":
        return _contains_any(window, AI_AGENT_CONTEXT_TERMS)

    if framework == "crewai" and component == "task":
        return _contains_any(window, AI_TASK_CONTEXT_TERMS)

    return True


def _make_item(
    rule,
    filepath,
    line,
    evidence,
    tools,
    memory,
    human_approval,
    asset_scope,
):
    return {
        "bom_type": "ABOM",
        "framework": rule["framework"],
        "component": rule["component"],
        "category": rule["category"],
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "tools_detected": tools,
        "memory_detected": memory,
        "human_approval_detected": human_approval,
        "asset_scope": asset_scope,
        "validation_only": asset_scope == "validation",
        "risk": rule["risk"],
        "recommendation": (
            "Review agent permissions, tool execution boundaries, "
            "memory usage, and human approval controls."
        ),
    }


def scan_file(filepath):
    path = Path(filepath)

    if not _should_scan(path):
        return []

    try:
        source = path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, UnicodeError):
        return []

    if not source.strip():
        return []

    lines = source.splitlines()
    findings = []
    asset_scope = _path_scope(path)

    for rule in ABOM_RULES:
        for pattern in rule["patterns"]:
            try:
                regex = re.compile(
                    pattern,
                    re.IGNORECASE | re.MULTILINE,
                )
            except re.error:
                continue

            for match in regex.finditer(source):
                line_no = _line_for_offset(source, match.start())

                evidence = (
                    lines[line_no - 1]
                    if 0 <= line_no - 1 < len(lines)
                    else ""
                )

                if _looks_like_comment_or_type_declaration(path, evidence):
                    continue

                window = _nearby_window(lines, line_no)

                # Generic Agent(...) must have explicit AI/agent context.
                if (
                    rule["framework"] == "CrewAI"
                    and rule["component"] == "Agent"
                    and GENERIC_AGENT_RE.search(match.group(0))
                    and not _contains_any(window, AI_AGENT_CONTEXT_TERMS)
                ):
                    continue

                # Generic Task(...) must have AI/agent context.
                if (
                    rule["framework"] == "CrewAI"
                    and rule["component"] == "Task"
                    and GENERIC_TASK_RE.search(match.group(0))
                    and not _contains_any(window, AI_TASK_CONTEXT_TERMS)
                ):
                    continue

                if not _rule_allowed(rule, evidence, window, path):
                    continue

                findings.append(
                    _make_item(
                        rule,
                        str(path),
                        line_no,
                        evidence,
                        _tool_hints(window),
                        _memory_hints(window),
                        _human_approval(window),
                        asset_scope,
                    )
                )

    return deduplicate(findings)


def deduplicate(items):
    seen = set()
    final = []

    for item in items:
        key = (
            item.get("framework"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
            item.get("asset_scope"),
        )

        if key in seen:
            continue

        seen.add(key)
        final.append(item)

    return final


def _iter_scannable_files(target: Path):
    """
    Single directory traversal.

    Path.rglob() is avoided because the old implementation repeatedly entered
    very large dependency trees before _should_scan() could reject files.
    """
    if target.is_file():
        if _should_scan(target):
            yield target
        return

    if not target.exists():
        return

    # os.walk gives us directory pruning before descending into node_modules,
    # vendor, build, dist, etc.
    import os

    for root, dirs, files in os.walk(target):
        dirs[:] = [
            d for d in dirs
            if d.lower() not in EXCLUDED_DIRS
        ]

        root_path = Path(root)

        for filename in files:
            path = root_path / filename

            if path.suffix.lower() not in SCANNABLE_EXT:
                continue

            if _is_excluded(path):
                continue

            yield path


def generate_abom(target_path):
    target = Path(target_path)

    if target.is_file():
        return scan_file(str(target))

    if not target.exists():
        return []

    results = []

    for path in _iter_scannable_files(target):
        results.extend(scan_file(str(path)))

    return deduplicate(results)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument(
        "--output",
        default="abom.json",
    )
    args = parser.parse_args()

    abom = generate_abom(args.target)

    with open(
        args.output,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            abom,
            f,
            indent=2,
        )

    print(f"[ABOM] Items found: {len(abom)}")
    print(f"[ABOM] Output written: {args.output}")
