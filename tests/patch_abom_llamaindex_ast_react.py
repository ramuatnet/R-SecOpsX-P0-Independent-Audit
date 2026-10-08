from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

text = src.read_text(encoding="utf-8-sig")

old = '''    "llama_index": {"VectorStoreIndex":"Query Engine","GPTVectorStoreIndex":"Query Engine"},'''

new = '''    "llama_index": {
        "VectorStoreIndex":"Query Engine",
        "GPTVectorStoreIndex":"Query Engine",
        "ReActAgent":"ReAct Agent",
    },'''

if old not in text:
    raise SystemExit(
        "ERROR: Expected llama_index AST_COMPONENTS mapping was not found. "
        "No source change made."
    )

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_llamaindex_ast_react_{stamp}.py"

shutil.copy2(src, backup)

text = text.replace(old, new, 1)

src.write_text(text, encoding="utf-8")

print("[PASS] Added LlamaIndex ReActAgent AST mapping")
print("[PASS] Existing VectorStoreIndex/GPTVectorStoreIndex mappings preserved")
print(f"[BACKUP] {backup}")
