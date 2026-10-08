from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from pathlib import Path

SCANNABLE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb"}

ABOM_RULES = [
    {"framework":"LangChain","component":"Agent Executor","patterns":[r"\bAgentExecutor\b",r"\binitialize_agent\b",r"\bcreate_openai_functions_agent\b",r"\bcreate_react_agent\b"],"category":"Agent Framework","risk":"HIGH"},
    {"framework":"LangChain","component":"Tool","patterns":[r"\bTool\s*\(",r"\bDynamicTool\s*\(",r"\bStructuredTool\s*\("],"category":"Tool Execution","risk":"HIGH"},
    {"framework":"CrewAI","component":"Agent","patterns":[r"\bAgent\s*\("],"category":"Agent Framework","risk":"HIGH"},
    {"framework":"CrewAI","component":"Crew","patterns":[r"\bCrew\s*\("],"category":"Agent Orchestration","risk":"HIGH"},
    {"framework":"CrewAI","component":"Task","patterns":[r"\bTask\s*\("],"category":"Agent Tasking","risk":"MEDIUM"},
    {"framework":"AutoGen","component":"Assistant Agent","patterns":[r"\bAssistantAgent\s*\("],"category":"Agent Framework","risk":"HIGH"},
    {"framework":"AutoGen","component":"User Proxy Agent","patterns":[r"\bUserProxyAgent\s*\("],"category":"Agent Framework","risk":"HIGH"},
    {"framework":"LlamaIndex","component":"Query Engine","patterns":[r"\bas_query_engine\s*\(",r"\bVectorStoreIndex\b",r"\bGPTVectorStoreIndex\b"],"category":"Retrieval Agent","risk":"HIGH"},
]

TOOL_HINTS = ["shell","filesystem","file","command","terminal","exec","browser","http","request","api","database","sql"]
MEMORY_HINTS = ["memory","conversationbuffer","chatmemory","vectorstore"]
HUMAN_APPROVAL_HINTS = ["human","approval","review","confirm","authorize"]

EXCLUDED_DIRS = {
    ".git",".svn",".hg",".venv","venv","env",".env",".tox",".cache","__pycache__",
    "node_modules","vendor","third_party","build","dist","coverage",".next",".nuxt"
}
VALIDATION_DIRS = {"tests","test","examples","example"}
VALIDATION_FILE_HINTS = {"codefixes","challenge","challenges","fixture","fixtures","sample","samples","benchmark"}

GENERIC_AGENT_RE = re.compile(r"\b(?:Agent|agent)\s*\(", re.IGNORECASE)
GENERIC_TASK_RE = re.compile(r"\bTask\s*\(", re.IGNORECASE)

AI_AGENT_CONTEXT_TERMS = (
    "agent","agentexecutor","assistantagent","userproxyagent","crewai","langchain",
    "autogen","llamaindex","llama_index","toolcalling","tool_call","react_agent"
)
AI_TASK_CONTEXT_TERMS = (
    "agent","agentexecutor","crewai","langchain","autogen","tasking",
    "task_agent","agent_task","llm","tool","prompt"
)
AI_TOOL_CONTEXT_TERMS = (
    "langchain","crewai","autogen","llamaindex","llama_index","ai-sdk","@ai-sdk",
    "tool(","tool ","structuredtool","dynamictool","functiontool","agent","llm"
)

AST_COMPONENTS = {
    "crewai": {"Agent":"Agent","Crew":"Crew","Task":"Task"},
    "langchain": {
        "AgentExecutor":"Agent Executor",
        "initialize_agent":"Agent Executor",
        "create_openai_functions_agent":"Agent Executor",
        "create_react_agent":"Agent Executor",
        "Tool":"Tool",
        "DynamicTool":"Tool",
        "StructuredTool":"Tool",
    },
    "autogen": {"AssistantAgent":"Assistant Agent","UserProxyAgent":"User Proxy Agent"},
    "llama_index": {"VectorStoreIndex":"Query Engine","GPTVectorStoreIndex":"Query Engine"},
}

def _path_scope(path: Path) -> str:
    parts = {p.lower() for p in path.parts}
    if parts.intersection({"node_modules","vendor","third_party"}):
        return "dependency"
    if parts.intersection(VALIDATION_DIRS):
        return "validation"
    lowered = str(path).lower().replace("\\","/")
    if any(token in lowered for token in VALIDATION_FILE_HINTS):
        return "validation"
    return "production"

def _is_excluded(path: Path) -> bool:
    excluded = {x.lower() for x in EXCLUDED_DIRS}
    return bool({p.lower() for p in path.parts}.intersection(excluded))

def _should_scan(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in SCANNABLE_EXT and not _is_excluded(path)

def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1

def _nearby_window(lines, line_no, radius=8):
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end]).lower()

def _tool_hints(window):
    return sorted({h for h in TOOL_HINTS if h in window})

def _memory_hints(window):
    return sorted({h for h in MEMORY_HINTS if h in window})

def _human_approval(window):
    return any(h in window for h in HUMAN_APPROVAL_HINTS)

def _contains_any(window, terms):
    return any(term in window for term in terms)

def _looks_like_comment_or_type_declaration(path: Path, evidence: str) -> bool:
    stripped = evidence.strip()
    if stripped.startswith(("//","#","*","/*","*/","/**","* @")):
        return True
    if path.suffix.lower() == ".d.ts":
        return True
    return False

def _python_regex_match_is_string_or_comment(source: str, match_start: int) -> bool:
    try:
        import tokenize
        from io import StringIO
        lines = source.splitlines(True)
        for tok in tokenize.generate_tokens(StringIO(source).readline):
            if tok.type not in (tokenize.STRING, tokenize.COMMENT): continue
            (sl, sc), (el, ec) = tok.start, tok.end
            start = sum(len(x) for x in lines[:sl - 1]) + sc
            finish = sum(len(x) for x in lines[:el - 1]) + ec
            if start <= match_start < finish: return True
    except (SyntaxError, tokenize.TokenError, IndentationError): return False
    return False

def _generic_crewai_evidence_is_valid(path: Path, source: str, match, line_no: int) -> bool:
    if path.suffix.lower() != ".py": return True
    if _python_regex_match_is_string_or_comment(source, match.start()): return False
    try: tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError): return False
    imports = _python_import_map(tree)
    if any(str(v).lower() == "crewai" or str(v).lower().startswith("crewai.") for v in imports.values()): return True
    lines = source.splitlines()
    line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    return bool(re.search(r"\bcrewai\s*\.\s*(Agent|Task)\s*\(", line, re.IGNORECASE))

def _rule_allowed(rule, evidence, window, path):
    component = rule["component"].lower()
    framework = rule["framework"].lower()
    if component in {"agent executor","assistant agent","user proxy agent","query engine","crew"}:
        return True
    if framework == "langchain" and component == "tool":
        return _contains_any(window, AI_TOOL_CONTEXT_TERMS)
    if framework == "crewai" and component == "agent":
        return _contains_any(window, AI_AGENT_CONTEXT_TERMS)
    if framework == "crewai" and component == "task":
        return _contains_any(window, AI_TASK_CONTEXT_TERMS)
    return True

def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,
               detection_mode="REGEX", import_resolution=None, confidence="MEDIUM"):
    """
    Canonical ABOM finding constructor.

    Guarantees:
      - legacy ABOM fields
      - deterministic component_id
      - evidence_type
      - confidence_level
      - compatibility with AST/import/regex detection
    """

    framework = str(rule.get("framework", ""))
    component = str(rule.get("component", ""))
    category = str(rule.get("category", ""))
    filepath = str(filepath)
    evidence = str(evidence or "").strip()

    mode = str(detection_mode or "REGEX").upper()

    evidence_type = []

    if "AST" in mode:
        evidence_type.append("AST")

    if "IMPORT_RESOLUTION" in mode:
        evidence_type.append("IMPORT_RESOLUTION")

    if "REGEX" in mode:
        evidence_type.append("REGEX")

    if not evidence_type:
        evidence_type.append("REGEX")

    # Deterministic component identity.
    identity = "|".join([
        framework.lower(),
        component.lower(),
        filepath.replace("\\", "/").lower(),
        str(line),
    ])

    component_id = "ABOM-" + hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:16].upper()

    item = {
        "bom_type": "ABOM",
        "component_id": component_id,

        "framework": framework,
        "component": component,
        "category": category,

        "file": filepath,
        "line": line,
        "evidence": evidence,

        "evidence_type": evidence_type,
        "detection_mode": mode,

        "confidence": confidence,
        "confidence_level": confidence,

        "tools_detected": list(tools or []),
        "memory_detected": list(memory or []),
        "human_approval_detected": bool(human_approval),

        "asset_scope": asset_scope,
        "validation_only": asset_scope == "validation",

        "risk": rule.get("risk", "MEDIUM"),

        "recommendation": (
            "Review agent permissions, tool execution boundaries, "
            "memory usage, and human approval controls."
        ),
    }

    if import_resolution:
        item["import_resolution"] = import_resolution

    return item

def _framework_from_module(module: str):
    m = (module or "").lower().replace("-","_")
    if m == "crewai" or m.startswith("crewai."):
        return "CrewAI"
    if m == "langchain" or m.startswith("langchain."):
        return "LangChain"
    if m in {"autogen","pyautogen"} or m.startswith("autogen."):
        return "AutoGen"
    if m in {"llama_index","llamaindex"} or m.startswith("llama_index."):
        return "LlamaIndex"
    return None

def _python_import_map(tree):
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for a in node.names:
                if a.name != "*":
                    imports[a.asname or a.name] = f"{module}.{a.name}".strip(".")
    return imports

def _ast_attr(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _ast_attr(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""

def _ast_findings(path: Path, source: str, asset_scope: str):
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError):
        return []
    imports = _python_import_map(tree)
    results = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        symbol = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
        root = func.id if isinstance(func, ast.Name) else _ast_attr(func).split(".")[0]
        resolved = imports.get(symbol, "")
        module = imports.get(root, root)
        fw = _framework_from_module(module)
        component = None
        resolution = None
        if fw and symbol in AST_COMPONENTS.get(module.lower().split(".")[0], {}):
            component = AST_COMPONENTS[module.lower().split(".")[0]][symbol]
            resolution = f"{symbol} -> {module}"
        elif resolved:
            parts = resolved.split(".")
            if len(parts) >= 2:
                fw2 = _framework_from_module(".".join(parts[:-1]))
                sym = parts[-1]
                if fw2 and sym in AST_COMPONENTS.get((fw2 or "").lower().replace("llamaindex","llama_index"), {}):
                    component = AST_COMPONENTS[(fw2 or "").lower().replace("llamaindex","llama_index")][sym]
                    fw = fw2
                    resolution = f"{symbol} -> {resolved}"
        if not fw or not component:
            continue
        rule = next((r for r in ABOM_RULES if r["framework"] == fw and r["component"] == component), None)
        if not rule:
            continue
        lines = source.splitlines()
        evidence = lines[getattr(node,"lineno",1)-1] if lines else ""
        window = _nearby_window(lines, getattr(node,"lineno",1))
        results.append(_make_item(rule,str(path),getattr(node,"lineno",1),evidence,
                                  _tool_hints(window),_memory_hints(window),_human_approval(window),
                                  asset_scope,"AST+IMPORT_RESOLUTION",resolution,"HIGH"))
    return results

def scan_file(filepath):
    path = Path(filepath)
    if not _should_scan(path):
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    if not source.strip():
        return []
    lines = source.splitlines()
    findings = []
    asset_scope = _path_scope(path)

    # Legacy regex detection is retained intentionally.
    for rule in ABOM_RULES:
        for pattern in rule["patterns"]:
            try:
                regex = re.compile(pattern,re.IGNORECASE|re.MULTILINE)
            except re.error:
                continue
            for match in regex.finditer(source):
                line_no = _line_for_offset(source,match.start())
                evidence = lines[line_no-1] if 0 <= line_no-1 < len(lines) else ""
                if _looks_like_comment_or_type_declaration(path,evidence):
                    continue
                window = _nearby_window(lines,line_no)
                if rule["framework"] == "CrewAI" and rule["component"] in {"Agent", "Task"}:
                    if not _generic_crewai_evidence_is_valid(path, source, match, line_no):
                        continue
                if not _rule_allowed(rule,evidence,window,path):
                    continue
                findings.append(_make_item(rule,str(path),line_no,evidence,_tool_hints(window),
                                           _memory_hints(window),_human_approval(window),asset_scope,
                                           "REGEX","", "HIGH" if rule["framework"] != "CrewAI" else "MEDIUM"))

    # AST/import resolution augments, never replaces, legacy coverage.
    if path.suffix.lower() == ".py":
        findings.extend(_ast_findings(path,source,asset_scope))

    return deduplicate(findings)

def deduplicate(items):
    seen = set()
    final = []
    for item in items:
        key = (item.get("framework"),item.get("component"),item.get("file"),
               item.get("line"),item.get("asset_scope"))
        if key in seen:
            # Preserve strongest evidence on duplicate occurrence.
            existing = next((x for x in final if (
                x.get("framework"),x.get("component"),x.get("file"),x.get("line"),x.get("asset_scope")
            ) == key),None)
            if existing:
                modes = set(str(existing.get("detection_mode","")).split("+"))
                modes.update(str(item.get("detection_mode","")).split("+"))
                existing["detection_mode"] = "+".join(sorted(x for x in modes if x))
                if item.get("confidence") == "HIGH":
                    existing["confidence"] = "HIGH"
                if item.get("import_resolution"):
                    existing["import_resolution"] = item["import_resolution"]
            continue
        seen.add(key)
        final.append(item)
    return final

def _iter_scannable_files(target: Path):
    if target.is_file():
        if _should_scan(target):
            yield target
        return
    if not target.exists():
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d.lower() not in EXCLUDED_DIRS]
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
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output",default="abom.json")
    args = parser.parse_args()
    abom = generate_abom(args.target)
    with open(args.output,"w",encoding="utf-8") as f:
        json.dump(abom,f,indent=2)
    print(f"[ABOM] Items found: {len(abom)}")
    print(f"[ABOM] Output written: {args.output}")
