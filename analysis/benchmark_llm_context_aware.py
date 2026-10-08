import sys
from pathlib import Path
import time
import importlib.util
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

MODULE_PATH = PROJECT_ROOT / "scanner" / "llm_security_context_aware.py"
spec = importlib.util.spec_from_file_location("llm_security_context_aware", MODULE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to load scanner: {MODULE_PATH}")
llm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llm)

target = Path(r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64")

files = []
for p in target.rglob("*"):
    if not p.is_file() or not llm._should_scan(p):
        continue
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue
    files.append((str(p), text))

print("Scanner-scope files:", len(files))

t0 = time.time()
results = []
for filepath, content in files:
    results.extend(llm.scan_llm_file(filepath, content))
elapsed = time.time() - t0

contexts = Counter(r.get("context_class", "UNKNOWN") for r in results)
actionable = sum(1 for r in results if r.get("actionable"))
contextual = len(results) - actionable

print("Raw LLM findings:", len(results))
print("Actionable candidates:", actionable)
print("Contextual/non-actionable:", contextual)
print("Seconds:", round(elapsed, 2))
print("\nContext distribution:")
for key, count in sorted(contexts.items()):
    print(f"  {key:<24} {count}")
