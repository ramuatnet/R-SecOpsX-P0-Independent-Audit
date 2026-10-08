from pathlib import Path
from tempfile import TemporaryDirectory
from scanner import abom

CASES = {
    "crewai_direct": """
import crewai
x = crewai.Agent(role="writer", goal="write")
""",

    "crewai_module_alias": """
import crewai as c
x = c.Agent(role="writer", goal="write")
""",

    "crewai_class_alias": """
from crewai import Agent as CrewAgent
x = CrewAgent(role="writer", goal="write")
""",

    "crewai_both": """
import crewai
from crewai import Agent as CrewAgent

a = CrewAgent(role="analyst", goal="analyze")
b = crewai.Agent(role="writer", goal="write")
""",

    "llama_react_direct": """
from llama_index.core.agent import ReActAgent

agent = ReActAgent.from_tools(tools)
""",

    "llama_react_alias": """
from llama_index.core.agent import ReActAgent as RAgent

agent = RAgent.from_tools(tools)
""",

    "langchain_executor": """
from langchain.agents import AgentExecutor

executor = AgentExecutor(agent=agent, tools=tools)
""",

    "langchain_executor_alias": """
from langchain.agents import AgentExecutor as Executor

executor = Executor(agent=agent, tools=tools)
""",

    "langchain_react_factory": """
from langchain.agents import create_react_agent

agent = create_react_agent(llm, tools, prompt)
""",

    "langchain_tool": """
from langchain.tools import Tool

tool = Tool(name="search", func=search, description="Search")
""",

    "autogen_assistant": """
from autogen import AssistantAgent

agent = AssistantAgent(name="assistant")
""",

    "autogen_alias": """
from autogen import AssistantAgent as AAgent

agent = AAgent(name="assistant")
""",

    "negative_local_agent": """
class Agent:
    pass

x = Agent()
""",

    "negative_comment": """
# crewai.Agent(role="fake")
# ReActAgent.from_tools(tools)
""",

    "negative_string": """
text = "crewai.Agent(role='fake')"
text2 = "ReActAgent.from_tools(tools)"
""",

    "negative_unrelated_method": """
class ReActAgent:
    def from_tools(self):
        pass

agent = ReActAgent()
agent.from_tools()
""",
}


def check_case(name, source):
    with TemporaryDirectory(prefix="abom_matrix_") as td:
        path = Path(td) / f"{name}.py"
        path.write_text(source, encoding="utf-8")

        rows = abom.scan_file(str(path))

        print()
        print("=" * 80)
        print(name)
        print("=" * 80)
        print("COUNT =", len(rows))

        for row in rows:
            print(
                f"framework={row.get('framework')!r} | "
                f"component={row.get('component')!r} | "
                f"line={row.get('line')} | "
                f"detection={row.get('detection_mode')} | "
                f"evidence_type={row.get('evidence_type')} | "
                f"resolution={row.get('import_resolution')!r}"
            )

        return rows


print("=" * 80)
print("R-SECOPSX V11 ABOM ALIAS / METHOD / NEGATIVE MATRIX")
print("=" * 80)

results = {}

for name, source in CASES.items():
    results[name] = check_case(name, source)

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)

positive = [
    "crewai_direct",
    "crewai_module_alias",
    "crewai_class_alias",
    "crewai_both",
    "llama_react_direct",
    "llama_react_alias",
    "langchain_executor",
    "langchain_executor_alias",
    "langchain_react_factory",
    "langchain_tool",
    "autogen_assistant",
    "autogen_alias",
]

negative = [
    "negative_local_agent",
    "negative_comment",
    "negative_string",
    "negative_unrelated_method",
]

failures = []

for name in positive:
    rows = results[name]
    if not rows:
        failures.append(f"{name}: expected positive finding")
        continue

    ast_or_import = [
        r for r in rows
        if "AST" in (r.get("evidence_type") or [])
        and "IMPORT_RESOLUTION" in (r.get("evidence_type") or [])
    ]

    if not ast_or_import:
        failures.append(
            f"{name}: finding exists but lacks AST+IMPORT_RESOLUTION"
        )

for name in negative:
    rows = results[name]
    if rows:
        failures.append(
            f"{name}: unexpected finding count={len(rows)}"
        )

print()

if failures:
    print("[FAIL] ABOM MATRIX")
    for failure in failures:
        print(" -", failure)
    raise SystemExit(1)

print("[PASS] All positive AST/import-resolution cases")
print("[PASS] All negative semantic cases")
print("[PASS] Alias resolution")
print("[PASS] Method resolution")
print("[PASS] AST/import provenance")
print("[PASS] ABOM ALIAS/METHOD/NEGATIVE MATRIX")
