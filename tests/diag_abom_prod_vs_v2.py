from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scanner.abom as prod
import scanner.abom_v2 as v2

root = Path(tempfile.mkdtemp(prefix="abom_prod_compare_"))
p = root / "crew.py"

p.write_text(
    """from crewai import Agent as CrewAgent
agent = CrewAgent(role="analyst", goal="analyze")
""",
    encoding="utf-8",
)

print("ROOT =", ROOT)
print("FILE =", p)
print()

prod_rows = prod.scan_file(str(p))
v2_rows = v2.scan_file(str(p))

print("=== PRODUCTION ABOM ===")
print("COUNT =", len(prod_rows))
for row in prod_rows:
    print(row)

print()
print("=== ABOM V2 ===")
print("COUNT =", len(v2_rows))
for row in v2_rows:
    print(row)

print()
print("=== CONTRACT COMPARISON ===")

def contract(row):
    return {
        "bom_type": row.get("bom_type"),
        "framework": row.get("framework"),
        "component": row.get("component"),
        "category": row.get("category"),
        "risk": row.get("risk"),
        "detection_mode": row.get("detection_mode"),
        "confidence": row.get("confidence"),
        "confidence_level": row.get("confidence_level"),
        "component_id": row.get("component_id"),
        "evidence_type": row.get("evidence_type"),
        "import_resolution": row.get("import_resolution"),
    }

print("PRODUCTION_CONTRACTS:")
for row in prod_rows:
    print(contract(row))

print()
print("V2_CONTRACTS:")
for row in v2_rows:
    print(contract(row))

prod_valid = all(
    r.get("bom_type") == "ABOM"
    and r.get("component_id", "").startswith("ABOM-")
    and r.get("confidence_level") in ("HIGH", "MEDIUM", "LOW")
    for r in prod_rows
)

v2_valid = all(
    r.get("bom_type") == "ABOM"
    and r.get("component_id", "").startswith("ABOM-")
    and r.get("confidence_level") in ("HIGH", "MEDIUM", "LOW")
    for r in v2_rows
)

print()
print("PRODUCTION_VALID =", prod_valid)
print("V2_VALID =", v2_valid)

print()
print("DIFFERENTIAL_TEST_COMPLETE")
