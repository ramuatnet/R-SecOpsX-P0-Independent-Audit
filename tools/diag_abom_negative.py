from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scanner.abom_v2 as abom_v2

root = Path(tempfile.mkdtemp(prefix="abom_neg_diag_"))
p = root / "negative.py"

p.write_text(
    "# Agent(role='fake')\n"
    "text = \"crewai.Agent(role='fake')\"\n"
    "def agent():\n"
    "    return 1\n",
    encoding="utf-8",
)

print("MODULE=", abom_v2.__file__)
print("FILE=", p)
print("SOURCE:")
print(p.read_text(encoding="utf-8"))

rows = abom_v2.scan_file(str(p))

print("NEGATIVE_COUNT=", len(rows))

for row in rows:
    print(row)
