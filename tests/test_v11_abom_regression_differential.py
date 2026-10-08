from pathlib import Path
import importlib.util
import tempfile
import json
import sys

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
CURRENT = ROOT / "scanner" / "abom.py"

# Use the pre-canonical-contract source as the differential baseline.
BACKUP = ROOT / "backup" / "abom.py.before_canonical_contract_20261005-052813.py"

if not BACKUP.exists():
    raise SystemExit(f"[FAIL] Differential baseline not found: {BACKUP}")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = load_module("abom_legacy", BACKUP)

sys.path.insert(0, str(ROOT))
from scanner import abom as current


def normalize(row):
    """
    Fields that represent actual detection semantics.

    V11-only contract fields are intentionally excluded here.
    """
    return {
        "framework": row.get("framework"),
        "component": row.get("component"),
        "category": row.get("category"),
        "line": row.get("line"),
        "evidence": row.get("evidence"),
        "risk": row.get("risk"),
        "import_resolution": row.get("import_resolution"),
        "asset_scope": row.get("asset_scope"),
        "validation_only": row.get("validation_only"),
    }


def write(path, text):
    path.write_text(text, encoding="utf-8")


root = Path(tempfile.mkdtemp(prefix="abom_diff_v11_"))

fixtures = {
    "crewai_alias.py": (
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "a = CrewAgent(role='analyst', goal='analyze')\n"
        "b = crewai.Agent(role='writer', goal='write')\n"
    ),

    "crewai_task.py": (
        "from crewai import Agent, Task\n"
        "agent = Agent(role='analyst', goal='analyze')\n"
        "task = Task(description='perform analysis', agent=agent)\n"
    ),

    "negative.py": (
        "# CrewAI Agent documentation only\n"
        "class Agent:\n"
        "    pass\n"
        "\n"
        "text = 'This file describes an Agent framework.'\n"
    ),
}

print("=" * 78)
print("R-SECOPSX V11 ABOM REGRESSION / DIFFERENTIAL VALIDATION")
print("=" * 78)
print(f"BASELINE = {BACKUP}")
print(f"CURRENT  = {CURRENT}")
print()

total = 0
passed = 0
failed = 0

for filename, source in fixtures.items():
    path = root / filename
    write(path, source)

    old_rows = legacy.scan_file(str(path))
    new_rows = current.scan_file(str(path))

    old_norm = sorted(
        [normalize(x) for x in old_rows],
        key=lambda x: (
            x.get("framework") or "",
            x.get("component") or "",
            x.get("line") or 0,
            x.get("evidence") or "",
        ),
    )

    new_norm = sorted(
        [normalize(x) for x in new_rows],
        key=lambda x: (
            x.get("framework") or "",
            x.get("component") or "",
            x.get("line") or 0,
            x.get("evidence") or "",
        ),
    )

    total += 1

    print(f"[CASE] {filename}")
    print(f"       baseline findings = {len(old_rows)}")
    print(f"       current findings  = {len(new_rows)}")

    if old_norm != new_norm:
        failed += 1
        print("       [FAIL] Legacy semantic output changed")

        print("       --- BASELINE ---")
        print(json.dumps(old_norm, indent=2, default=str))

        print("       --- CURRENT ---")
        print(json.dumps(new_norm, indent=2, default=str))
        print()
        continue

    # V11 contract validation on every current finding.
    contract_ok = True

    for row in new_rows:
        if not str(row.get("component_id", "")).startswith("ABOM-"):
            contract_ok = False
            print("       [FAIL] Missing/invalid component_id")

        if not row.get("evidence_type"):
            contract_ok = False
            print("       [FAIL] Missing evidence_type")

        if not row.get("confidence_level"):
            contract_ok = False
            print("       [FAIL] Missing confidence_level")

    if not contract_ok:
        failed += 1
        continue

    passed += 1
    print("       [PASS] Legacy semantic behavior preserved")
    print("       [PASS] V11 canonical contract present")
    print()

print("=" * 78)
print(f"CASES  : {total}")
print(f"PASSED : {passed}")
print(f"FAILED : {failed}")
print("=" * 78)

if failed:
    raise SystemExit("[FAIL] ABOM differential validation failed.")

print("ABOM_REGRESSION_DIFFERENTIAL_ACCEPTED")
