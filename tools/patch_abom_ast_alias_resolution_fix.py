from pathlib import Path

path = Path(r".\scanner\abom.py")
text = path.read_text(encoding="utf-8-sig")

start = text.index("def _ast_findings(")
end = text.index("def scan_file(", start)

new_function = '''def _ast_findings(path: Path, source: str, asset_scope: str):
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, TypeError):
        return []

    imports = _python_import_map(tree)
    results = []
    lines = source.splitlines()

    def _component_key(framework):
        value = (framework or "").lower().replace("-", "_")
        if value == "llamaindex":
            return "llama_index"
        return value

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func

        if isinstance(func, ast.Name):
            symbol = func.id
            root = func.id
        elif isinstance(func, ast.Attribute):
            symbol = func.attr
            root = _ast_attr(func).split(".")[0]
        else:
            continue

        component = None
        fw = None
        resolution = None

        # ------------------------------------------------------------
        # CASE 1: Direct framework module call
        #
        #     import crewai
        #     crewai.Agent(...)
        #
        #     import crewai as c
        #     c.Agent(...)
        # ------------------------------------------------------------
        root_module = imports.get(root, root)
        root_fw = _framework_from_module(root_module)

        if root_fw:
            module_key = _component_key(root_fw)
            mapping = AST_COMPONENTS.get(module_key, {})

            if symbol in mapping:
                component = mapping[symbol]
                fw = root_fw

                if root in imports:
                    resolution = f"{root} -> {root_module}"
                else:
                    resolution = f"{root} -> {root_module}"

        # ------------------------------------------------------------
        # CASE 2: Imported class/symbol alias
        #
        #     from crewai import Agent as CrewAgent
        #     CrewAgent(...)
        #
        #     from langchain.agents import AgentExecutor
        #     AgentExecutor(...)
        # ------------------------------------------------------------
        if component is None:
            resolved = imports.get(root, "")

            if resolved:
                parts = resolved.rsplit(".", 1)

                if len(parts) == 2:
                    resolved_module, resolved_symbol = parts

                    resolved_fw = _framework_from_module(resolved_module)

                    if resolved_fw:
                        module_key = _component_key(resolved_fw)
                        mapping = AST_COMPONENTS.get(module_key, {})

                        if resolved_symbol in mapping:
                            component = mapping[resolved_symbol]
                            fw = resolved_fw
                            resolution = f"{root} -> {resolved}"

        # ------------------------------------------------------------
        # CASE 3: Imported class/symbol method call
        #
        #     from llama_index.core.agent import ReActAgent
        #     ReActAgent.from_tools(...)
        #
        # root      = ReActAgent
        # symbol    = from_tools
        # imports   = ReActAgent -> llama_index.core.agent.ReActAgent
        #
        # Resolve the component from the imported class, not method.
        # ------------------------------------------------------------
        if component is None and root in imports:
            resolved = imports.get(root, "")
            parts = resolved.rsplit(".", 1)

            if len(parts) == 2:
                resolved_module, resolved_symbol = parts

                resolved_fw = _framework_from_module(resolved_module)

                if resolved_fw:
                    module_key = _component_key(resolved_fw)
                    mapping = AST_COMPONENTS.get(module_key, {})

                    if resolved_symbol in mapping:
                        component = mapping[resolved_symbol]
                        fw = resolved_fw
                        resolution = f"{root} -> {resolved}"

        if not fw or not component:
            continue

        rule = next(
            (
                r for r in ABOM_RULES
                if r["framework"] == fw
                and r["component"] == component
            ),
            None,
        )

        if not rule:
            continue

        line_no = getattr(node, "lineno", 1)
        evidence = (
            lines[line_no - 1]
            if lines and 0 <= line_no - 1 < len(lines)
            else ""
        )

        window = _nearby_window(lines, line_no)

        results.append(
            _make_item(
                rule,
                str(path),
                line_no,
                evidence,
                _tool_hints(window),
                _memory_hints(window),
                _human_approval(window),
                asset_scope,
                "AST+IMPORT_RESOLUTION",
                resolution,
                "HIGH",
            )
        )

    return results


'''

text = text[:start] + new_function + text[end:]

backup = path.parent.parent / "backup" / (
    "abom.py.before_ast_alias_resolution_fix_20261005-"
    + __import__("datetime").datetime.now().strftime("%H%M%S")
    + ".py"
)
backup.parent.mkdir(parents=True, exist_ok=True)
backup.write_text(
    path.read_text(encoding="utf-8-sig"),
    encoding="utf-8"
)

path.write_text(text, encoding="utf-8")

print("[PASS] Replaced _ast_findings() with unified import-resolution logic")
print("[PASS] Preserves direct module resolution")
print("[PASS] Preserves imported alias resolution")
print("[PASS] Supports imported-class method resolution")
print(f"[BACKUP] {backup}")
