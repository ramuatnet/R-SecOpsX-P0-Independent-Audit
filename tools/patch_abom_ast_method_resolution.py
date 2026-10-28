from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_ast_method_resolution_{stamp}.py"

text = src.read_text(encoding="utf-8-sig")

old = '''        if fw and symbol in AST_COMPONENTS.get(module.lower().split(".")[0], {}):
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
'''

new = '''        module_key = module.lower().split(".")[0].replace("llamaindex", "llama_index")

        # Direct imported symbol resolution:
        #   from llama_index.core import VectorStoreIndex
        #   VectorStoreIndex(...)
        if fw and symbol in AST_COMPONENTS.get(module_key, {}):
            component = AST_COMPONENTS[module_key][symbol]
            resolution = f"{symbol} -> {module}"

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
            parts = resolved.split(".")
            if len(parts) >= 2:
                fw2 = _framework_from_module(".".join(parts[:-1]))
                sym = parts[-1]
                fw2_key = (fw2 or "").lower().replace(
                    "llamaindex", "llama_index"
                )

                if fw2 and sym in AST_COMPONENTS.get(fw2_key, {}):
                    component = AST_COMPONENTS[fw2_key][sym]
                    fw = fw2
                    resolution = f"{symbol} -> {resolved}"
'''

if old not in text:
    raise SystemExit(
        "ERROR: Expected _ast_findings resolution block was not found. "
        "No source change made."
    )

shutil.copy2(src, backup)

text = text.replace(old, new, 1)
src.write_text(text, encoding="utf-8")

print("[PASS] Added generic AST imported-class method resolution")
print("[PASS] Supports ReActAgent.from_tools() style calls")
print("[PASS] Existing direct and alias resolution preserved")
print(f"[BACKUP] {backup}")
