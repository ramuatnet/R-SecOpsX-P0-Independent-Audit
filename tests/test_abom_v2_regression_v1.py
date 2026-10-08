from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom_v2


def assert_common(row):
    assert row.get("bom_type") == "ABOM", row
    assert row.get("component_id", "").startswith("ABOM-"), row
    assert row.get("evidence_type"), row
    assert row.get("confidence_level") in {"HIGH", "MEDIUM", "LOW"}, row
    assert row.get("asset_scope") in {"production", "validation"}, row


def framework_rows(rows, framework):
    return [
        x for x in rows
        if x.get("framework", "").lower() == framework.lower()
    ]


def main():
    root = Path(tempfile.mkdtemp(prefix="abom_v2_regression_"))

    # ---------------------------------------------------------
    # 1. CrewAI
    # ---------------------------------------------------------
    crew = root / "crew.py"
    crew.write_text(
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "a = CrewAgent(role='analyst', goal='analyze')\n"
        "b = crewai.Agent(role='writer', goal='write')\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(crew))
    print("CREWAI =", len(rows))
    for row in rows:
        print(row)

    cr = framework_rows(rows, "CrewAI")
    assert len(cr) >= 2, cr

    for row in cr:
        assert_common(row)
        assert row["component"] == "Agent", row
        assert "AST" in row.get("evidence_type", []), row

    print("[PASS] CrewAI")


    # ---------------------------------------------------------
    # 2. LangChain
    # ---------------------------------------------------------
    langchain = root / "langchain_app.py"
    langchain.write_text(
        "from langchain.agents import AgentExecutor\n"
        "from langchain.tools import Tool\n"
        "executor = AgentExecutor(agent=None, tools=[])\n"
        "tool = Tool(name='search', func=lambda x: x)\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(langchain))
    print("LANGCHAIN =", len(rows))
    for row in rows:
        print(row)

    lr = framework_rows(rows, "LangChain")
    assert lr, lr

    for row in lr:
        assert_common(row)

    print("[PASS] LangChain")


    # ---------------------------------------------------------
    # 3. AutoGen
    # ---------------------------------------------------------
    autogen = root / "autogen_app.py"
    autogen.write_text(
        "from autogen import AssistantAgent\n"
        "assistant = AssistantAgent(name='assistant')\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(autogen))
    print("AUTOGEN =", len(rows))
    for row in rows:
        print(row)

    ar = framework_rows(rows, "AutoGen")
    assert ar, ar

    for row in ar:
        assert_common(row)

    print("[PASS] AutoGen")


    # ---------------------------------------------------------
    # 4. LlamaIndex
    # ---------------------------------------------------------
    llama = root / "llamaindex_app.py"
    llama.write_text(
        "from llama_index.core import VectorStoreIndex\n"
        "index = VectorStoreIndex([])\n"
        "engine = index.as_query_engine()\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(llama))
    print("LLAMAINDEX =", len(rows))
    for row in rows:
        print(row)

    lir = framework_rows(rows, "LlamaIndex")
    assert lir, lir

    for row in lir:
        assert_common(row)

    print("[PASS] LlamaIndex")


    # ---------------------------------------------------------
    # 5. Comments and strings must not produce findings
    # ---------------------------------------------------------
    negative = root / "negative.py"
    negative.write_text(
        "# Agent(role='fake')\n"
        "# AgentExecutor(agent=None)\n"
        "text = \"crewai.Agent(role='fake')\"\n"
        "text2 = \"AssistantAgent(name='fake')\"\n"
        "text3 = \"AgentExecutor(agent=None)\"\n"
        "def normal_function():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(negative))
    print("NEGATIVE =", len(rows))
    for row in rows:
        print(row)

    assert not rows, rows

    print("[PASS] Comment/string suppression")


    # ---------------------------------------------------------
    # 6. Normal Python must not generate ABOM
    # ---------------------------------------------------------
    clean = root / "clean.py"
    clean.write_text(
        "def calculate(a, b):\n"
        "    return a + b\n"
        "\n"
        "value = calculate(1, 2)\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(clean))
    print("CLEAN =", len(rows))

    assert not rows, rows

    print("[PASS] Clean Python")


    # ---------------------------------------------------------
    # 7. Malformed Python must not crash scanner
    # ---------------------------------------------------------
    malformed = root / "malformed.py"
    malformed.write_text(
        "from crewai import Agent\n"
        "agent = Agent(\n"
        "this is intentionally malformed\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(malformed))
    print("MALFORMED =", len(rows))

    assert isinstance(rows, list)

    print("[PASS] Malformed Python resilience")


    # ---------------------------------------------------------
    # 8. Contract validation across all findings
    # ---------------------------------------------------------
    all_rows = []

    for path in [crew, langchain, autogen, llama]:
        all_rows.extend(abom_v2.scan_file(str(path)))

    assert all_rows

    component_ids = [
        x.get("component_id")
        for x in all_rows
    ]

    assert all(component_ids)
    assert all(x.startswith("ABOM-") for x in component_ids)

    assert all(
        isinstance(x.get("evidence_type"), list)
        and x.get("evidence_type")
        for x in all_rows
    )

    assert all(
        x.get("confidence_level") in {"HIGH", "MEDIUM", "LOW"}
        for x in all_rows
    )

    print("[PASS] Global ABOM V2 contract")


    # ---------------------------------------------------------
    # 9. Deduplication
    # ---------------------------------------------------------
    duplicate_fixture = root / "duplicate.py"
    duplicate_fixture.write_text(
        "from crewai import Agent\n"
        "agent = Agent(role='analyst', goal='analyze')\n",
        encoding="utf-8",
    )

    rows = abom_v2.scan_file(str(duplicate_fixture))

    keys = [
        (
            x.get("framework"),
            x.get("component"),
            x.get("file"),
            x.get("line"),
        )
        for x in rows
    ]

    assert len(keys) == len(set(keys)), rows

    print("[PASS] Deduplication")


    print("")
    print("============================================================")
    print("ABOM_V2_REGRESSION_V1_ACCEPTED")
    print("============================================================")


if __name__ == "__main__":
    main()
