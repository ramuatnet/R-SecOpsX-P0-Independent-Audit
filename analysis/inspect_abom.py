import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.abom import generate_abom

target = r"D:\Data\Code test\juice-shop-20.2.0_node22_win32_x64"

x = generate_abom(target)

print("ABOM findings:", len(x))

for i in x:
    print(
        i.get("component"),
        "|",
        i.get("category"),
        "|",
        i.get("file"),
        ":",
        i.get("line"),
        "|",
        i.get("evidence", "")[:250]
    )
