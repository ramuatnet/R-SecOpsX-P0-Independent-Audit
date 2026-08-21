import ast
from pathlib import Path

EXCLUDE_PARTS = {
    ".venv",
    "venv",
    "env",
    "reports",
    "__pycache__",
    ".git",
    "dist",
    "build",
}

mods = set()

for p in Path(".").rglob("*.py"):
    parts = {x.lower() for x in p.parts}
    if parts & EXCLUDE_PARTS:
        continue

    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text)
    except Exception:
        continue

    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.add(n.module.split(".")[0])

Path("reports").mkdir(exist_ok=True)
Path("reports/clean_import_inventory.txt").write_text(
    "\n".join(sorted(mods)),
    encoding="utf-8",
)

print("DONE", len(mods))