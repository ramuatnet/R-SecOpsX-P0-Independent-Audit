from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom_v2

root = Path(tempfile.mkdtemp(prefix="abom_regex_guard_"))
p = root / "negative.py"

source = """# Agent(role='fake')
text = "crewai.Agent(role='fake')"
def agent():
    return 1
"""

p.write_text(source, encoding="utf-8")

print("FILE:", p)
print("SOURCE:")
print(source)

rows = abom_v2.scan_file(str(p))

print("COUNT =", len(rows))

for row in rows:
    print(row)
