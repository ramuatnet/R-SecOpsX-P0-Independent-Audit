import sys
from pathlib import Path
import time
import importlib.util

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MODULE_PATH = PROJECT_ROOT / "scanner" / "llm_security_optimized.py"

# When this benchmark file is copied into analysis/, it loads the optimized
# scanner directly, without changing the production scanner yet.
spec = importlib.util.spec_from_file_location("llm_security_optimized", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to load optimized scanner: {MODULE_PATH}")

llm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llm)

from scanner.walk import walk

target = Path(r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64")

files = []
for p, _s, _m in walk(target, exts=None, ignore=frozenset(), max_bytes=None):
    if not p.is_file():
        continue
    if not llm._should_scan(p):
        continue
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    files.append((str(p), text))

print("Scanner-scope files:", len(files))

t = time.time()
results = []
for filepath, content in files:
    results.extend(llm.scan_llm_file(filepath, content))

elapsed = time.time() - t

print("LLM findings:", len(results))
print("Seconds:", round(elapsed, 2))
