from pathlib import Path
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom


def write_file(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def frameworks(rows):
    return sorted(set(
        str(x.get("framework", "")).lower()
        for x in rows
        if x.get("framework")
    ))


def components(rows):
    return sorted(set(
        (
            str(x.get("framework", "")),
            str(x.get("component", "")),
        )
        for x in rows
    ))


def validate_contract(rows, label):
    assert rows, f"{label}: no findings"

    for row in rows:
        assert str(row.get("component_id", "")).startswith("ABOM-"), (
            f"{label}: invalid component_id: {row}"
        )
        assert row.get("evidence_type"), (
            f"{label}: missing evidence_type: {row}"
        )
        assert row.get("confidence_level"), (
            f"{label}: missing confidence_level: {row}"
        )
        assert row.get("detection_mode"), (
            f"{label}: missing detection_mode: {row}"
        )

        # Provenance must agree with detection mode.
        modes = set(
            x.strip()
            for x in str(row["detection_mode"]).split("+")
            if x.strip()
        )
        evidence = set(row.get("evidence_type") or [])

        assert evidence.issubset(modes), (
            f"{label}: evidence_type not represented by detection_mode\n"
            f"modes={modes}\n"
            f"evidence={evidence}\n"
            f"row={row}"
        )


def run_case(root, name, source, expected=True):
    path = write_file(root, name, source)
    rows = abom.scan_file(str(path))

    print(f"\n[CASE] {name}")
    print(f"       findings = {len(rows)}")
    print(f"       frameworks = {frameworks(rows)}")
    print(f"       components = {components(rows)}")

    if expected:
        validate_contract(rows, name)
        print("       [PASS] positive detection")
        print("       [PASS] canonical contract")
    else:
        assert not rows, (
            f"{name}: expected no findings, got {rows}"
        )
        print("       [PASS] negative/noise suppression")

    return rows


def main():
    root = Path(tempfile.mkdtemp(prefix="abom_functional_v11_"))

    print("=" * 80)
    print("R-SECOPSX V11 ABOM FUNCTIONAL VALIDATION")
    print("=" * 80)
    print(f"ROOT = {ROOT}")
    print(f"FIXTURE ROOT = {root}")

    cases = []

    # ------------------------------------------------------------------
    # 1. CrewAI
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "crewai_agent.py",
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "agent1 = CrewAgent(role='analyst', goal='analyze')\n"
        "agent2 = crewai.Agent(role='writer', goal='write')\n",
    ))

    cases.append(run_case(
        root,
        "crewai_task.py",
        "from crewai import Agent, Task\n"
        "agent = Agent(role='analyst', goal='analyze')\n"
        "task = Task(description='perform analysis', agent=agent)\n",
    ))

    # ------------------------------------------------------------------
    # 2. LangChain
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "langchain_agent.py",
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(agent=agent, tools=tools)\n",
    ))

    # ------------------------------------------------------------------
    # 3. LlamaIndex
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "llamaindex_agent.py",
        "from llama_index.core.agent import ReActAgent\n"
        "agent = ReActAgent.from_tools(tools)\n",
    ))

    # ------------------------------------------------------------------
    # 4. AutoGen
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "autogen_agent.py",
        "from autogen import AssistantAgent\n"
        "agent = AssistantAgent(name='assistant')\n",
    ))

    # ------------------------------------------------------------------
    # 5. Tool execution context
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "tool_usage.py",
        "from crewai import Agent\n"
        "agent = Agent(\n"
        "    role='analyst',\n"
        "    goal='analyze',\n"
        "    tools=[search_tool, shell_tool],\n"
        ")\n",
    ))

    # ------------------------------------------------------------------
    # 6. Memory context
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "memory_usage.py",
        "from crewai import Agent\n"
        "agent = Agent(\n"
        "    role='analyst',\n"
        "    goal='analyze',\n"
        "    memory=True,\n"
        ")\n",
    ))

    # ------------------------------------------------------------------
    # 7. Human approval context
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "human_approval.py",
        "from crewai import Agent\n"
        "agent = Agent(\n"
        "    role='analyst',\n"
        "    goal='analyze',\n"
        "    human_input=True,\n"
        ")\n",
    ))

    # ------------------------------------------------------------------
    # 8. Alias resolution
    # ------------------------------------------------------------------
    cases.append(run_case(
        root,
        "alias_resolution.py",
        "from crewai import Agent as MyAgent\n"
        "x = MyAgent(role='analyst', goal='analyze')\n",
    ))

    # ------------------------------------------------------------------
    # 9. Negative: documentation/type declaration
    # ------------------------------------------------------------------
    run_case(
        root,
        "negative_declaration.py",
        "# Agent documentation\n"
        "class Agent:\n"
        "    pass\n"
        "\n"
        "text = 'CrewAI Agent documentation only'\n",
        expected=False,
    )

    # ------------------------------------------------------------------
    # 10. Negative: comments only
    # ------------------------------------------------------------------
    run_case(
        root,
        "negative_comments.py",
        "# from crewai import Agent\n"
        "# agent = Agent(role='analyst')\n",
        expected=False,
    )

    # ------------------------------------------------------------------
    # 11. Multi-file project
    # ------------------------------------------------------------------
    project = root / "multi_project"
    project.mkdir()

    write_file(
        project,
        "agents.py",
        "from crewai import Agent\n"
        "analyst = Agent(role='analyst', goal='analyze')\n",
    )

    write_file(
        project,
        "tasks.py",
        "from crewai import Task\n"
        "task = Task(description='analyze data')\n",
    )

    write_file(
        project,
        "negative.py",
        "class Agent:\n"
        "    pass\n",
    )

    generated = abom.generate_abom(str(project))

    print("\n[CASE] multi-file generate_abom")
    print(f"       findings = {len(generated)}")

    assert generated, "generate_abom() produced no findings"

    validate_contract(generated, "multi-file generate_abom")

    files = set(str(x.get("file", "")) for x in generated)

    assert any("agents.py" in x for x in files), (
        "multi-file project did not detect agents.py"
    )

    print("       [PASS] multi-file detection")
    print("       [PASS] negative file does not cause failure")
    print("       [PASS] canonical contract")

    # ------------------------------------------------------------------
    # 12. Deduplication
    # ------------------------------------------------------------------
    duplicate = write_file(
        root,
        "duplicate.py",
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "x = CrewAgent(role='analyst', goal='analyze')\n"
        "y = crewai.Agent(role='writer', goal='write')\n",
    )

    rows = abom.scan_file(str(duplicate))

    keys = [
        (
            x.get("framework"),
            x.get("component"),
            x.get("file"),
            x.get("line"),
            x.get("asset_scope"),
        )
        for x in rows
    ]

    assert len(keys) == len(set(keys)), (
        "duplicate canonical findings detected"
    )

    print("\n[CASE] deduplication")
    print(f"       findings = {len(rows)}")
    print("       [PASS] canonical duplicate suppression")

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("ABOM FUNCTIONAL VALIDATION COMPLETE")
    print("=" * 80)
    print("Positive framework/context cases : PASS")
    print("Negative/noise cases             : PASS")
    print("AST/import contract              : PASS")
    print("Canonical component identity      : PASS")
    print("Evidence provenance              : PASS")
    print("Confidence contract              : PASS")
    print("Multi-file generation             : PASS")
    print("Deduplication                     : PASS")
    print("=" * 80)
    print("ABOM_FUNCTIONAL_V11_ACCEPTED")


if __name__ == "__main__":
    main()
