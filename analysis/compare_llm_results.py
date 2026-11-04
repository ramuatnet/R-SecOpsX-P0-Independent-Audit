try:
    from analysis.spans import WINDOW_220
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_220
import sys
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

target = Path(r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64")

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

original = load("llm_original", ROOT / "scanner" / "llm_security.py")
optimized = load("llm_optimized", ROOT / "scanner" / "llm_security_optimized.py")

from scanner.walk import walk

files = []

for p, _s, _m in walk(target, exts=None, ignore=frozenset(), max_bytes=None):
    if not p.is_file():
        continue

    if not original._should_scan(p):
        continue

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        continue

    files.append((str(p), text))

def key(x):
    return (
        x.get("file"),
        x.get("line"),
        x.get("rule_id"),
        x.get("title"),
        x.get("evidence"),
    )

original_results = []
optimized_results = []

for filepath, content in files:
    original_results.extend(original.scan_llm_file(filepath, content))
    optimized_results.extend(optimized.scan_llm_file(filepath, content))

orig = {key(x): x for x in original_results}
opt = {key(x): x for x in optimized_results}

missing = [x for k, x in orig.items() if k not in opt]

print("Original:", len(original_results))
print("Optimized:", len(optimized_results))
print("Missing from optimized:", len(missing))
print()

for x in missing:
    print(
        x.get("rule_id"),
        "|",
        x.get("title"),
        "|",
        x.get("file"),
        ":",
        x.get("line"),
        "|",
        str(x.get("evidence", ""))[:WINDOW_220]
    )
