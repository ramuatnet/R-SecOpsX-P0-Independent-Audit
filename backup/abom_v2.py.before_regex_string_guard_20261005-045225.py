from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any


# ============================================================
# R-SecOpsX V11 - ABOM V2
# Fresh implementation
# ============================================================

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
        "patterns": [r"\bAgent\s*\("],
        "category": "Agent Framework",
        "risk": "HIGH",
    },
    {
        "framework": "CrewAI",
        "component": "Crew",
        "patterns": [r"\bCrew\s*\("],
        "category": "Agent Orchestration",
        "risk": "HIGH",
    },
    {
        "framework": "CrewAI",
        "component": "Task",
        "patterns": [r"\bTask\s*\("],
        "category": "Agent Tasking",
        "risk": "MEDIUM",
    },
    {
        "framework": "AutoGen",
        "component": "Assistant Agent",
        "patterns": [r"\bAssistantAgent\s*\("],
        "category": "Agent Framework",
        "risk": "HIGH",
    },
    {
        "framework": "AutoGen",
        "component": "User Proxy Agent",
        "patterns": [r"\bUserProxyAgent\s*\("],
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


FRAMEWORK_MODULES = {
    "crewai": "CrewAI",
    "langchain": "LangChain",
    "langchain_core": "LangChain",
    "langchain_community": "LangChain",
    "autogen": "AutoGen",
    "pyautogen": "AutoGen",
    "llama_index": "LlamaIndex",
    "llamaindex": "LlamaIndex",
}


COMPONENTS = {
    ("CrewAI", "Agent"): ("Agent", "Agent Framework", "HIGH"),
    ("CrewAI", "Crew"): ("Crew", "Agent Orchestration", "HIGH"),
    ("CrewAI", "Task"): ("Task", "Agent Tasking", "MEDIUM"),
    ("LangChain", "AgentExecutor"): ("Agent Executor", "Agent Framework", "HIGH"),
    ("LangChain", "Tool"): ("Tool", "Tool Execution", "HIGH"),
    ("AutoGen", "AssistantAgent"): ("Assistant Agent", "Agent Framework", "HIGH"),
    ("AutoGen", "UserProxyAgent"): ("User Proxy Agent", "Agent Framework", "HIGH"),
    ("LlamaIndex", "VectorStoreIndex"): ("Query Engine", "Retrieval Agent", "HIGH"),
}


TOOL_TERMS = {
    "tool",
    "tools",
    "execute",
    "exec",
    "command",
    "shell",
    "subprocess",
    "request",
    "api",
    "http",
    "sql",
}


MEMORY_TERMS = {
    "memory",
    "conversationbuffer",
    "conversationbufferwindow",
    "vectorstore",
    "retriever",
    "retrieval",
    "chat_history",
    "history",
}


HUMAN_APPROVAL_TERMS = {
    "human_approval",
    "human_approve",
    "human_input",
    "human_input_required",
    "approval_required",
    "requires_approval",
    "humaninloop",
    "human_in_loop",
}


def _asset_scope(path: Path) -> str:
    text = str(path).replace("\\", "/").lower()

    validation_markers = (
        "/tests/",
        "/test/",
        "/fixtures/",
        "/benchmark",
        "/validation",
        "/corpus/",
        "/analysis/",
    )

    return "validation" if any(x in text for x in validation_markers) else "production"


def _is_validation(path: Path) -> bool:
    return _asset_scope(path) == "validation"


def _safe_source(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _module_root(module: str) -> str:
    return (module or "").lower().replace("-", "_").split(".")[0]


def _framework(module: str) -> str | None:
    return FRAMEWORK_MODULES.get(_module_root(module))


def _import_map(tree: ast.AST) -> dict[str, str]:
    result: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                result[alias.asname or alias.name] = f"{module}.{alias.name}"

    return result


def _call_name(node: ast.Call) -> str:
    fn = node.func

    if isinstance(fn, ast.Name):
        return fn.id

    if isinstance(fn, ast.Attribute):
        parts = []
        cur: Any = fn

        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value

        if isinstance(cur, ast.Name):
            parts.append(cur.id)

        return ".".join(reversed(parts))

    return ""


def _resolve_call(
    node: ast.Call,
    imports: dict[str, str],
) -> tuple[str | None, str | None, str | None]:
    name = _call_name(node)

    if not name:
        return None, None, None

    if "." in name:
        root, symbol = name.split(".", 1)
        target = imports.get(root, root)
        fw = _framework(target)

        if fw:
            if fw == "CrewAI" and symbol in {"Agent", "Crew", "Task"}:
                return fw, symbol, f"{symbol} -> {target}"

            if fw == "LangChain" and symbol in {
                "Tool",
                "DynamicTool",
                "StructuredTool",
                "AgentExecutor",
            }:
                component = (
                    "AgentExecutor"
                    if symbol == "AgentExecutor"
                    else "Tool"
                )
                return fw, component, f"{symbol} -> {target}"

            if fw == "AutoGen" and symbol in {
                "AssistantAgent",
                "UserProxyAgent",
            }:
                return fw, symbol, f"{symbol} -> {target}"

            if fw == "LlamaIndex" and symbol in {
                "VectorStoreIndex",
                "GPTVectorStoreIndex",
            }:
                return fw, "VectorStoreIndex", f"{symbol} -> {target}"

    target = imports.get(name)

    if target:
        parts = target.rsplit(".", 1)

        if len(parts) == 2:
            module, symbol = parts
            fw = _framework(module)

            if fw:
                if fw == "CrewAI" and symbol in {"Agent", "Crew", "Task"}:
                    return fw, symbol, f"{name} -> {target}"

                if fw == "LangChain" and symbol in {
                    "Tool",
                    "DynamicTool",
                    "StructuredTool",
                    "AgentExecutor",
                }:
                    component = (
                        "AgentExecutor"
                        if symbol == "AgentExecutor"
                        else "Tool"
                    )
                    return fw, component, f"{name} -> {target}"

                if fw == "AutoGen" and symbol in {
                    "AssistantAgent",
                    "UserProxyAgent",
                }:
                    return fw, symbol, f"{name} -> {target}"

                if fw == "LlamaIndex" and symbol in {
                    "VectorStoreIndex",
                    "GPTVectorStoreIndex",
                }:
                    return fw, "VectorStoreIndex", f"{name} -> {target}"

    return None, None, None


def _line(source: str, lineno: int) -> str:
    lines = source.splitlines()
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


def _context(source: str, lineno: int, radius: int = 5) -> str:
    lines = source.splitlines()
    lo = max(0, lineno - 1 - radius)
    hi = min(len(lines), lineno + radius)
    return "\n".join(lines[lo:hi]).lower()


def _hints(context: str) -> tuple[list[str], list[str], bool]:
    tools = sorted(
        x for x in TOOL_TERMS
        if re.search(r"\b" + re.escape(x) + r"\b", context)
    )

    memory = sorted(
        x for x in MEMORY_TERMS
        if re.search(r"\b" + re.escape(x) + r"\b", context)
    )

    approval = any(
        re.search(r"\b" + re.escape(x) + r"\b", context)
        for x in HUMAN_APPROVAL_TERMS
    )

    return tools, memory, approval


def _component_id(
    framework: str,
    component: str,
    filepath: str,
    line: int,
) -> str:
    raw = f"{framework}|{component}|{filepath}|{line}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
    return f"ABOM-{digest}"


def _make_item(
    *,
    framework: str,
    component: str,
    category: str,
    risk: str,
    filepath: str,
    line: int,
    evidence: str,
    detection_mode: str,
    confidence: str,
    evidence_type: list[str],
    import_resolution: str | None,
    tools: list[str],
    memory: list[str],
    human_approval: bool,
    asset_scope: str,
) -> dict[str, Any]:

    item = {
        "bom_type": "ABOM",
        "framework": framework,
        "component": component,
        "category": category,
        "file": filepath,
        "line": line,
        "evidence": evidence.strip(),
        "tools_detected": tools,
        "memory_detected": memory,
        "human_approval_detected": human_approval,
        "asset_scope": asset_scope,
        "validation_only": asset_scope == "validation",
        "risk": risk,
        "recommendation": (
            "Review agent permissions, tool execution boundaries, "
            "memory usage, and human approval controls."
        ),
        "detection_mode": detection_mode,
        "confidence": confidence,

        # V11 additions
        "component_id": _component_id(
            framework,
            component,
            filepath,
            line,
        ),
        "evidence_type": sorted(set(evidence_type)),
        "confidence_level": confidence,
    }

    if import_resolution:
        item["import_resolution"] = import_resolution

    return item


def _regex_findings(
    path: Path,
    source: str,
    asset_scope: str,
) -> list[dict[str, Any]]:

    results = []

    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError):
        tree = None

    imports = _import_map(tree) if tree else {}

    for rule in ABOM_RULES:
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_no = source.count("\n", 0, match.start()) + 1
                line_text = _line(source, line_no)

                # Ignore comments.
                stripped = line_text.lstrip()
                if stripped.startswith("#"):
                    continue

                # Python AST string literal suppression.
                if path.suffix.lower() == ".py" and tree:
                    try:
                        token = ast.get_source_segment(source, tree)
                    except Exception:
                        token = None

                framework = rule["framework"]
                component = rule["component"]

                # CrewAI Agent/Task must have real CrewAI context.
                if framework == "CrewAI":
                    if not (
                        re.search(
                            r"\bcrewai\s*\.\s*"
                            + re.escape(component)
                            + r"\s*\(",
                            line_text,
                            re.IGNORECASE,
                        )
                        or any(
                            _framework(v) == "CrewAI"
                            for v in imports.values()
                        )
                    ):
                        continue

                ctx = _context(source, line_no)
                tools, memory, approval = _hints(ctx)

                results.append(
                    _make_item(
                        framework=framework,
                        component=component,
                        category=rule["category"],
                        risk=rule["risk"],
                        filepath=str(path),
                        line=line_no,
                        evidence=line_text,
                        detection_mode="REGEX",
                        confidence="MEDIUM",
                        evidence_type=["REGEX"],
                        import_resolution=None,
                        tools=tools,
                        memory=memory,
                        human_approval=approval,
                        asset_scope=asset_scope,
                    )
                )

    return results


def _ast_findings(
    path: Path,
    source: str,
    asset_scope: str,
) -> list[dict[str, Any]]:

    if path.suffix.lower() != ".py":
        return []

    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError):
        return []

    imports = _import_map(tree)
    results = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        framework, component, resolution = _resolve_call(node, imports)

        if not framework or not component:
            continue

        meta = COMPONENTS.get((framework, component))

        if not meta:
            continue

        _, category, risk = meta

        line_no = getattr(node, "lineno", 1)
        line_text = _line(source, line_no)
        ctx = _context(source, line_no)

        tools, memory, approval = _hints(ctx)

        results.append(
            _make_item(
                framework=framework,
                component=component,
                category=category,
                risk=risk,
                filepath=str(path),
                line=line_no,
                evidence=line_text,
                detection_mode="AST+IMPORT_RESOLUTION",
                confidence="HIGH",
                evidence_type=[
                    "AST",
                    "IMPORT_RESOLUTION",
                ],
                import_resolution=resolution,
                tools=tools,
                memory=memory,
                human_approval=approval,
                asset_scope=asset_scope,
            )
        )

    return results


def _deduplicate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []

    for row in rows:
        key = (
            row.get("framework"),
            row.get("component"),
            row.get("file"),
            row.get("line"),
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(row)

    return output


def scan_file(path: str) -> list[dict[str, Any]]:
    p = Path(path)

    if not p.is_file():
        return []

    source = _safe_source(p)
    asset_scope = _asset_scope(p)

    rows = []
    rows.extend(_ast_findings(p, source, asset_scope))

    # Regex is supplementary. AST findings remain authoritative.
    regex_rows = _regex_findings(p, source, asset_scope)

    existing = {
        (
            x["framework"],
            x["component"],
            x["file"],
            x["line"],
        )
        for x in rows
    }

    for row in regex_rows:
        key = (
            row["framework"],
            row["component"],
            row["file"],
            row["line"],
        )

        if key in existing:
            # Upgrade evidence instead of creating a duplicate.
            for existing_row in rows:
                if (
                    existing_row["framework"],
                    existing_row["component"],
                    existing_row["file"],
                    existing_row["line"],
                ) == key:
                    existing_row["detection_mode"] += "+REGEX"
                    existing_row["evidence_type"] = sorted(
                        set(existing_row["evidence_type"]) | {"REGEX"}
                    )
                    break
        else:
            rows.append(row)

    return _deduplicate(rows)


def generate_abom(target: str) -> list[dict[str, Any]]:
    root = Path(target)

    if root.is_file():
        return scan_file(str(root))

    if not root.is_dir():
        return []

    results = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
        }:
            continue

        results.extend(scan_file(str(path)))

    return _deduplicate(results)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="R-SecOpsX ABOM V2")
    parser.add_argument("target")
    parser.add_argument("-o", "--output", default="abom_v2.json")

    args = parser.parse_args()

    results = generate_abom(args.target)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    print(f"[ABOM V2] Items found: {len(results)}")
    print(f"[ABOM V2] Output: {args.output}")


if __name__ == "__main__":
    main()
