import sys
from pathlib import Path
import time

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import scanner.llm_security as llm

target = Path(r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64")

files = []

for p in target.rglob("*"):
    if not p.is_file():
        continue

    # Use the scanner's own file-scope logic if available.
    if hasattr(llm, "_should_scan") and not llm._should_scan(p):
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
