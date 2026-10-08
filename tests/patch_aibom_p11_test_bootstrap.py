from pathlib import Path

TEST = Path(r".\tests\test_v11_aibom_p11_asset_graph_contract.py")

text = TEST.read_text(encoding="utf-8-sig")

bootstrap = """from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

"""

if "PROJECT_ROOT = Path(__file__).resolve().parents[1]" in text:
    print("[INFO] Project-root bootstrap already present")
else:
    TEST.write_text(bootstrap + text, encoding="utf-8")
    print("[PASS] AI-BOM P1 project-root bootstrap added")

