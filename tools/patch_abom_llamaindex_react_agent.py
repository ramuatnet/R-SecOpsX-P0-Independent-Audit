from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

text = src.read_text(encoding="utf-8-sig")

new_rule = '    {"framework":"LlamaIndex","component":"ReAct Agent","patterns":[r"\\bReActAgent\\s*\\(",r"\\bReActAgent\\.from_tools\\s*\\("],"category":"Agent Framework","risk":"HIGH"},'

if '"component":"ReAct Agent"' in text:
    print("[INFO] LlamaIndex ReAct Agent rule already exists. No source change made.")
    raise SystemExit(0)

needle = '    {"framework":"LlamaIndex","component":"Query Engine","patterns":[r"\\bas_query_engine\\s*\\(",r"\\bVectorStoreIndex\\b",r"\\bGPTVectorStoreIndex\\b"],"category":"Retrieval Agent","risk":"HIGH"},'

if needle not in text:
    raise SystemExit(
        "ERROR: Exact LlamaIndex Query Engine rule was not found. "
        "No source change made."
    )

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_llamaindex_react_agent_{stamp}.py"

shutil.copy2(src, backup)

replacement = needle + "\n" + new_rule
text = text.replace(needle, replacement, 1)

src.write_text(text, encoding="utf-8")

print("[PASS] LlamaIndex ReAct Agent rule added")
print("[PASS] Existing Query Engine rule preserved")
print(f"[BACKUP] {backup}")
