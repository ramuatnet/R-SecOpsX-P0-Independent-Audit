from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom_v2


def check(rows, framework, component):
    return any(
        x.get("framework") == framework
        and x.get("component") == component
        for x in rows
    )


def main():
    root = Path(tempfile.mkdtemp(prefix="abom_v2_"))
    src = root / "crew.py"

    src.write_text(
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "a = CrewAgent(role='analyst', goal='analyze')\n"
        "b = crewai.Agent(role='writer', goal='write')\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(src))

    print("CREWAI_FINDINGS=", len(rows))
    for row in rows:
        print(row)

    assert rows
    assert check(rows, "CrewAI", "Agent")

    for row in rows:
        assert row["bom_type"] == "ABOM"
        assert row["component_id"].startswith("ABOM-")
        assert "AST" in row["evidence_type"]
        assert row["confidence_level"] == "HIGH"
        assert row["asset_scope"] == "production"
        assert row["validation_only"] is False

    assert any(
        "IMPORT_RESOLUTION" in x["evidence_type"]
        for x in rows
    )

    negative = root / "negative.py"
    negative.write_text(
        "# Agent(role='fake')\n"
        "text = \"crewai.Agent(role='fake')\"\n"
        "def agent():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    negative_rows = abom_v2.scan_file(str(negative))

    assert not any(
        x["framework"] == "CrewAI"
        and x["component"] == "Agent"
        for x in negative_rows
    )

    alias = root / "alias.py"
    alias.write_text(
        "from crewai import Agent as MyAgent\n"
        "agent = MyAgent(role='x', goal='y')\n",
        encoding="utf-8",
    )

    alias_rows = abom_v2.scan_file(str(alias))

    assert check(alias_rows, "CrewAI", "Agent")

    project = root / "project"
    project.mkdir()

    (project / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(role='x', goal='y')\n",
        encoding="utf-8",
    )

    generated = abom_v2.generate_abom(str(project))

    assert generated

    ids = [x["component_id"] for x in generated]
    assert len(ids) == len(set(ids))

    print("[PASS] CrewAI")
    print("[PASS] AST")
    print("[PASS] Import alias resolution")
    print("[PASS] component_id")
    print("[PASS] evidence_type")
    print("[PASS] confidence_level")
    print("[PASS] comment suppression")
    print("[PASS] string suppression")
    print("[PASS] generate_abom")
    print("[PASS] deduplication")
    print("ABOM_V2_ACCEPTED")


if __name__ == "__main__":
    main()
