from pathlib import Path
from datetime import datetime

path = Path(r".\scanner\abom.py")
text = path.read_text(encoding="utf-8-sig")

old = '''        # Method-call resolution through an imported class/symbol:
        #   from llama_index.core.agent import ReActAgent
        #   ReActAgent.from_tools(...)
        #
        # Here:
        #   symbol = "from_tools"
        #   root   = "ReActAgent"
        #
        # The framework component belongs to the imported root symbol,
        # not to the method name.
        elif fw and root in imports:
            root_module = imports.get(root, "")
            root_key = root_module.lower().split(".")[0].replace(
                "llamaindex", "llama_index"
            )

            root_fw = _framework_from_module(root_module)

            if root_fw and root in AST_COMPONENTS.get(root_key, {}):
                component = AST_COMPONENTS[root_key][root]
                fw = root_fw
                resolution = f"{root} -> {root_module}"

        # Imported symbol alias resolution:
        elif resolved:
'''

new = '''        # Imported symbol / alias resolution:
        #
        # Examples:
        #   from crewai import Agent as CrewAgent
        #   CrewAgent(...)
        #
        #   from llama_index.core import VectorStoreIndex as VSI
        #   VSI(...)
        #
        # The canonical component is the final imported symbol
        # (Agent / VectorStoreIndex), not the local alias.
        elif resolved:
            parts = resolved.split(".")
            if len(parts) >= 2:
                imported_symbol = parts[-1]
                imported_module = ".".join(parts[:-1])

                imported_fw = _framework_from_module(imported_module)
                imported_key = (
                    (imported_fw or "")
                    .lower()
                    .replace("llamaindex", "llama_index")
                )

                if (
                    imported_fw
                    and imported_symbol
                    in AST_COMPONENTS.get(imported_key, {})
                ):
                    component = AST_COMPONENTS[imported_key][imported_symbol]
                    fw = imported_fw
                    resolution = f"{symbol} -> {resolved}"

        # Method-call resolution through an imported class/symbol:
        #   from llama_index.core.agent import ReActAgent
        #   ReActAgent.from_tools(...)
        #
        # Here:
        #   symbol = "from_tools"
        #   root   = "ReActAgent"
        #
        # The framework component belongs to the imported root symbol,
        # not to the method name.
        elif fw and root in imports:
            root_module = imports.get(root, "")
            root_parts = root_module.split(".")
            root_symbol = root_parts[-1] if root_parts else ""
            root_base_module = ".".join(root_parts[:-1])

            root_fw = _framework_from_module(root_base_module)
            root_key = (
                (root_fw or "")
                .lower()
                .replace("llamaindex", "llama_index")
            )

            if (
                root_fw
                and root_symbol
                in AST_COMPONENTS.get(root_key, {})
            ):
                component = AST_COMPONENTS[root_key][root_symbol]
                fw = root_fw
                resolution = f"{root} -> {root_module}"

        # Imported symbol alias resolution fallback.
        elif resolved:
'''

if old not in text:
    raise SystemExit(
        "ERROR: Expected AST resolution block was not found. "
        "No source change made."
    )

backup_dir = path.parent.parent / "backup"
backup_dir.mkdir(exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_alias_resolution_fix_{stamp}.py"
backup.write_text(text, encoding="utf-8")

path.write_text(text.replace(old, new, 1), encoding="utf-8")

print("[PASS] Preserved LlamaIndex ReAct method resolution")
print("[PASS] Restored imported alias resolution")
print("[PASS] Added canonical imported-symbol resolution")
print(f"[BACKUP] {backup}")
