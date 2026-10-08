# R-SecOpsX V11 - ABOM clean implementation v1
# AI/Agent Bill of Materials
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules",
    ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"
}

FRAMEWORKS = {
    "crewai": {
        "components": {
            "Agent": "agent",
            "Task": "task",
            "Crew": "crew",
            "CrewAI": "framework",
        }
    },
    "langchain": {
        "components": {
            "AgentExecutor": "agent_executor",
            "initialize_agent": "agent_factory",
            "create_react_agent": "agent_factory",
            "create_tool_calling_agent": "agent_factory",
            "Tool": "tool",
        }
    },
    "autogen": {
        "components": {
            "AssistantAgent": "agent",
            "UserProxyAgent": "agent",
            "ConversableAgent": "agent",
        }
    },
    "llama_index": {
        "components": {
            "VectorStoreIndex": "retrieval_index",
            "ReActAgent": "agent",
            "FunctionCallingAgent": "agent",
        }
    },
}

JS_PATTERNS = (
    ("langchain", "AgentExecutor", "agent_executor"),
    ("langchain", "createReactAgent", "agent_factory"),
    ("langchain", "createToolCallingAgent", "agent_factory"),
    ("autogen", "AssistantAgent", "agent"),
    ("crewai", "Agent", "agent"),
)

def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8-sig", errors="replace")

def _is_excluded(path: Path) -> bool:
    return any(part in EXCLUDED_DIRS for part in path.parts)

def _norm(path: str) -> str:
    return str(path).replace("\\", "/")

def _component_id(framework: str, component: str, path: str, line: int) -> str:
    raw = "|".join((framework, component, _norm(path), str(line))).encode("utf-8")
    return "ABOM-" + hashlib.sha256(raw).hexdigest()[:24]

def _base(
    framework: str,
    component: str,
    component_type: str,
    path: str,
    line: int,
    evidence: Iterable[str],
    confidence: str,
) -> Dict[str, Any]:
    return {
        "framework": framework,
        "component": component,
        "component_type": component_type,
        "file": _norm(path),
        "line": int(line),
        "component_id": _component_id(framework, component, path, line),
        "evidence_type": sorted(set(evidence)),
        "confidence_level": confidence,
    }

def _python_imports(tree: ast.AST) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{module}.{a.name}".strip(".")
    return aliases

def _attribute_root(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            return root.id
    return None

def _attribute_full(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _attribute_full(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""

def _python_components(path: str, source: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, TypeError):
        return []

    imports = _python_imports(tree)
    findings: List[Dict[str, Any]] = []

    def add(framework: str, component: str, node: ast.AST, import_resolution: str):
        ctype = FRAMEWORKS[framework]["components"][component]
        evidence = ["AST"]
        if import_resolution:
            evidence.append("IMPORT_RESOLUTION")
        item = _base(
            framework, component, ctype, path,
            getattr(node, "lineno", 1),
            evidence,
            "HIGH" if import_resolution else "MEDIUM",
        )
        item["import_resolution"] = import_resolution
        findings.append(item)

    for node in ast.walk(tree):
        # from framework import Agent as CrewAgent; CrewAgent(...)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                symbol = func.id
                target = imports.get(symbol, "")
                for fw, spec in FRAMEWORKS.items():
                    for component in spec["components"]:
                        expected = f"{fw}.{component}"
                        if target.lower() == expected.lower():
                            add(fw, component, node, f"{symbol} -> {target}")
            elif isinstance(func, ast.Attribute):
                full = _attribute_full(func)
                parts = full.split(".")
                if len(parts) >= 2:
                    root = parts[0]
                    symbol = parts[-1]
                    module = imports.get(root, root)
                    for fw, spec in FRAMEWORKS.items():
                        if module.lower() in (fw.lower(), fw.replace("_",".").lower()):
                            if symbol in spec["components"]:
                                add(fw, symbol, node, f"{root} -> {module}")

        # import framework; framework.Agent(...) and qualified calls
        if isinstance(node, ast.ImportFrom):
            module = (node.module or "").lower()
            for alias in node.names:
                if alias.name == "*":
                    continue
                for fw, spec in FRAMEWORKS.items():
                    if module == fw.lower() or module.startswith(fw.lower() + "."):
                        if alias.name in spec["components"]:
                            # Import itself is supporting evidence; actual component
                            # instance/call is emitted above.
                            pass

    return findings

def _js_components(path: str, source: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for fw, component, ctype in JS_PATTERNS:
        pattern = re.compile(
            rf"\b{re.escape(component)}\b|\b{re.escape(component[:1].lower()+component[1:])}\b"
        )
        for m in pattern.finditer(source):
            line = source.count("\n", 0, m.start()) + 1
            item = _base(
                fw, component, ctype, path, line,
                ["TEXT_PATTERN"],
                "MEDIUM",
            )
            item["import_resolution"] = []
            findings.append(item)
            break
    return findings

def scan_file(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.is_file() or _is_excluded(p):
        return []

    source = _read_text(str(p))
    suffix = p.suffix.lower()

    if suffix == ".py":
        return deduplicate(_python_components(str(p), source))

    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return deduplicate(_js_components(str(p), source))

    return []

def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in findings:
        key = (
            item.get("framework"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result

def generate_abom(target: str) -> List[Dict[str, Any]]:
    root = Path(target)
    if root.is_file():
        return scan_file(str(root))

    if not root.exists():
        return []

    findings: List[Dict[str, Any]] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for name in files:
            p = Path(base) / name
            if p.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx"}:
                findings.extend(scan_file(str(p)))
    return deduplicate(findings)

def enrich_abom_payload(payload: Dict[str, Any], target: str) -> Dict[str, Any]:
    payload = dict(payload or {})
    payload["abom"] = generate_abom(target)
    return payload

__all__ = [
    "scan_file",
    "generate_abom",
    "deduplicate",
    "enrich_abom_payload",
]