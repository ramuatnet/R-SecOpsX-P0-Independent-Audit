from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom_v3


def main():
    root = Path(tempfile.mkdtemp(prefix="abom_v3_accept_"))

    positive = root / "crew.py"
    positive.write_text(
        "from crewai import Agent as CrewAgent\n"
        "from crewai import Task as CrewTask\n"
        "agent = CrewAgent(role='analyst', goal='analyze')\n"
        "task = CrewTask(description='analyze', agent=agent)\n",
        encoding="utf-8",
    )

    rows = abom_v3.scan_file(str(positive))

    assert rows, "V3 produced no findings"

    assert all(
        isinstance(x, dict)
        and x.get("bom_type") == "ABOM"
        for x in rows
    )

    enriched = [
        x for x in rows
        if x.get("component_id")
        and "AST" in x.get("evidence_type", [])
    ]

    assert enriched, rows

    assert all(
        x["component_id"].startswith("ABOM-")
        for x in enriched
    )

    assert all(
        x.get("confidence_level") in
        ("HIGH", "MEDIUM", "LOW")
        for x in enriched
    )

    resolved = [
        x for x in enriched
        if "IMPORT_RESOLUTION" in x.get("evidence_type", [])
    ]

    assert resolved, enriched
    assert all(
        x.get("import_resolution")
        for x in resolved
    )

    # --------------------------------------------------------
    # Negative source
    # --------------------------------------------------------

    negative = root / "negative.py"
    negative.write_text(
        "# crewai.Agent(role='fake')\n"
        "text = \"crewai.Agent(role='fake')\"\n"
        "def agent():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    negative_rows = abom_v3.scan_file(str(negative))

    assert not any(
        x.get("framework") == "CrewAI"
        and x.get("component") == "Agent"
        for x in negative_rows
    ), negative_rows

    # --------------------------------------------------------
    # Clean source
    # --------------------------------------------------------

    clean = root / "clean.py"
    clean.write_text(
        "def hello():\n"
        "    return 'hello'\n",
        encoding="utf-8",
    )

    assert abom_v3.scan_file(str(clean)) == []

    # --------------------------------------------------------
    # Malformed source
    # --------------------------------------------------------

    malformed = root / "malformed.py"
    malformed.write_text(
        "def broken(:\n"
        "    pass\n",
        encoding="utf-8",
    )

    malformed_rows = abom_v3.scan_file(str(malformed))
    assert isinstance(malformed_rows, list)

    # --------------------------------------------------------
    # Public API
    # --------------------------------------------------------

    assert callable(abom_v3.scan_file)
    assert callable(abom_v3.generate_abom)

    print("[PASS] V3 CrewAI detection")
    print("[PASS] V3 AST evidence")
    print("[PASS] V3 import resolution")
    print("[PASS] V3 component_id")
    print("[PASS] V3 confidence contract")
    print("[PASS] V3 negative suppression")
    print("[PASS] V3 clean source")
    print("[PASS] V3 malformed source resilience")
    print("[PASS] V3 public API")

    print("ABOM_V3_CANONICAL_ACCEPTED")


if __name__ == "__main__":
    main()
