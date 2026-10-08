from pathlib import Path
import shutil

path = Path(r".\tests\test_v11_llm01_decision_policy_v2.py")

if not path.exists():
    raise SystemExit("[ERROR] V2 acceptance test not found.")

text = path.read_text(encoding="utf-8-sig")

bootstrap = '''from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

'''

target = "from scanner.llm_security import scan_llm_file"

if target not in text:
    raise SystemExit("[ERROR] scanner import not found.")

if "PROJECT_ROOT = Path(__file__).resolve().parents[1]" in text:
    print("[INFO] Project-root bootstrap already present.")
else:
    backup = path.with_suffix(path.suffix + ".bak_direct_exec")
    shutil.copy2(path, backup)

    text = text.replace(target, bootstrap + target, 1)
    path.write_text(text, encoding="utf-8")

    print("[PASS] Direct-execution project-root bootstrap added")
    print(f"[BACKUP] {backup}")

