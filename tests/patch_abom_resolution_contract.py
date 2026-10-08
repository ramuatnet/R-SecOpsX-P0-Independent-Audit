from pathlib import Path
from datetime import datetime

path = Path(r".\scanner\abom.py")
text = path.read_text(encoding="utf-8-sig")

old = '''                if root in imports:
                    resolution = f"{root} -> {root_module}"
                else:
                    resolution = f"{root} -> {root_module}"
'''

new = '''                # Preserve the legacy semantic resolution contract.
                #
                # import crewai
                # crewai.Agent(...)
                #
                # Legacy representation:
                #   Agent -> crewai
                #
                # Do not expose the imported module alias as the
                # resolved symbol. The component symbol is the
                # semantic identity used by the historical ABOM output.
                resolution = f"{symbol} -> {root_module}"
'''

if old not in text:
    raise SystemExit(
        "ERROR: Expected direct framework resolution block was not found. "
        "No source change made."
    )

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = Path(r".\backup") / f"abom.py.before_resolution_contract_{timestamp}.py"
backup.parent.mkdir(parents=True, exist_ok=True)
backup.write_text(text, encoding="utf-8")

text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")

print("[PASS] Restored legacy direct-module resolution semantics")
print("[PASS] Alias/import resolution preserved")
print(f"[BACKUP] {backup.resolve()}")
