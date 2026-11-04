try:
    from analysis.spans import WINDOW_250
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_250
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.cbom import generate_cbom

target = r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64"

x = generate_cbom(target)

print("CBOM findings:", len(x))

for i in x:
    print(
        i.get("component"),
        "|",
        i.get("file"),
        ":",
        i.get("line"),
        "|",
        i.get("evidence", "")[:WINDOW_250]
    )
